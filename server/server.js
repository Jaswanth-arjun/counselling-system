require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');
const bcryptjs = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const multer = require('multer');
const path = require('path');

// Initialize Express app
const app = express();

// Middleware
app.use(cors({
    origin: [
        'http://localhost:5173',
        'http://localhost:5174',
        'http://127.0.0.1:5173',
        'http://127.0.0.1:5174'
    ]
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// Initialize Supabase
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY
);

// Configure multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
    const token = req.headers['x-auth-token'];

    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.id;
        req.userRole = decoded.role;
        req.userEmail = decoded.email;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid or expired token' });
    }
};

// ===========================
// AUTHENTICATION ROUTES
// ===========================

// Register Student
app.post('/api/auth/register/student', [
    body('email').isEmail(),
    body('password').isLength({ min: 6 }),
    body('name').notEmpty(),
    body('roll_no').notEmpty()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, password, name, roll_no } = req.body;

        // Hash password
        const hashedPassword = await bcryptjs.hash(password, 10);

        // Insert user
        const { data: user, error: userError } = await supabase
            .from('users')
            .insert([{
                email,
                password_hash: hashedPassword,
                name,
                roll_no,
                role: 'student',
                is_verified: false
            }])
            .select();

        if (userError) throw userError;

        // Insert student profile
        const { error: studentError } = await supabase
            .from('students')
            .insert([{
                id: user[0].id,
                roll_no,
                semester: 1,
                year: 1
            }]);

        if (studentError) throw studentError;

        // Create JWT token
        const token = jwt.sign({
            id: user[0].id,
            email: user[0].email,
            role: 'student',
            roll_no: user[0].roll_no
        }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.status(201).json({
            message: 'Student registered successfully',
            token,
            user: user[0]
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Register Counsellor (Admin only)
app.post('/api/admin/register-counsellor', verifyToken, [
    body('email').isEmail(),
    body('password').isLength({ min: 6 }),
    body('name').notEmpty(),
    body('counsellor_id').notEmpty()
], async (req, res) => {
    try {
        if (req.userRole !== 'admin') {
            return res.status(403).json({ error: 'Only admins can register counsellors' });
        }

        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, password, name, counsellor_id, assignments } = req.body;

        // Hash password
        const hashedPassword = await bcryptjs.hash(password, 10);

        // Insert user
        const { data: user, error: userError } = await supabase
            .from('users')
            .insert([{
                email,
                password_hash: hashedPassword,
                name,
                role: 'counsellor',
                is_verified: true
            }])
            .select();

        if (userError) throw userError;

        // Use first assignment for backward compatibility with single assignment fields
        const firstAssignment = assignments && assignments.length > 0 ? assignments[0] : {};

        // Insert counsellor profile
        const { error: counsellorError } = await supabase
            .from('counsellors')
            .insert([{
                id: user[0].id,
                counsellor_id,
                assigned_year: firstAssignment.assigned_year || 1,
                assigned_semester: firstAssignment.assigned_semester || 1,
                assigned_branch: firstAssignment.assigned_branch || '',
                assigned_section: firstAssignment.assigned_section || '',
                max_students: firstAssignment.max_students || 30,
                assignments: assignments || []
            }]);

        if (counsellorError) throw counsellorError;

        res.status(201).json({
            message: 'Counsellor registered successfully',
            user: user[0]
        });
    } catch (error) {
        console.error('Counsellor registration error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Login
app.post('/api/auth/login', [
    body('identifier').notEmpty(),
    body('password').notEmpty(),
    body('role').notEmpty()
], async (req, res) => {
    try {
        const { identifier, password, role } = req.body;

        // Get user - identifier can be email, roll_no, or counsellor_id
        let users = [];

        if (role === 'admin') {
            // Admins login with email only
            const { data: adminUsers, error: adminError } = await supabase
                .from('users')
                .select('*')
                .eq('role', 'admin')
                .eq('email', identifier);

            if (adminError) throw adminError;
            users = adminUsers || [];
        } else if (role === 'student') {
            // Students can login with email or roll_no
            let { data: studentUsers, error: emailError } = await supabase
                .from('users')
                .select('*')
                .eq('role', 'student')
                .eq('email', identifier);

            if (emailError) throw emailError;

            if (!studentUsers || studentUsers.length === 0) {
                // Try by roll_no
                const { data: rollUsers, error: rollError } = await supabase
                    .from('users')
                    .select('*')
                    .eq('role', 'student')
                    .eq('roll_no', identifier);

                if (rollError) throw rollError;
                users = rollUsers || [];
            } else {
                users = studentUsers;
            }
        } else if (role === 'counsellor') {
            // Counsellors can login with email or counsellor_id
            let { data: counsellorUsers, error: emailError } = await supabase
                .from('users')
                .select('*')
                .eq('role', 'counsellor')
                .eq('email', identifier);

            if (emailError) throw emailError;

            if (!counsellorUsers || counsellorUsers.length === 0) {
                // Try by counsellor_id
                const { data: counsellors, error: counsellorError } = await supabase
                    .from('counsellors')
                    .select('id')
                    .eq('counsellor_id', identifier);

                if (counsellorError) throw counsellorError;

                if (counsellors && counsellors.length > 0) {
                    const { data: usersByIdData, error: userError } = await supabase
                        .from('users')
                        .select('*')
                        .eq('id', counsellors[0].id);

                    if (userError) throw userError;
                    users = usersByIdData || [];
                }
            } else {
                users = counsellorUsers;
            }
        }

        if (!users || users.length === 0) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const user = users[0];

        // Verify password
        const isValidPassword = await bcryptjs.compare(password, user.password_hash);

        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Create JWT token
        const token = jwt.sign({
            id: user.id,
            email: user.email,
            role: user.role,
            roll_no: user.roll_no
        }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                role: user.role,
                roll_no: user.roll_no,
                is_verified: user.is_verified
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Verify Email
app.get('/api/auth/verify-email/:token', async (req, res) => {
    try {
        const { token } = req.params;

        const { data: users, error } = await supabase
            .from('users')
            .select('*')
            .eq('verification_token', token);

        if (error) throw error;

        if (!users || users.length === 0) {
            return res.status(400).json({ error: 'Invalid verification token' });
        }

        const user = users[0];

        // Update user verification status
        const { error: updateError } = await supabase
            .from('users')
            .update({ is_verified: true, verification_token: null })
            .eq('id', user.id);

        if (updateError) throw updateError;

        res.json({ message: 'Email verified successfully' });
    } catch (error) {
        console.error('Email verification error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ===========================
// STUDENT ROUTES
// ===========================

// Get Student Profile
app.get('/api/student/profile', verifyToken, async (req, res) => {
    try {
        const { data: student, error: studentError } = await supabase
            .from('students')
            .select('*')
            .eq('id', req.userId)
            .single();

        if (studentError) throw studentError;

        // Fetch user data separately
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('name, email, profile_image')
            .eq('id', req.userId)
            .single();

        if (userError) throw userError;

        // Combine user data with student data
        const combinedData = {
            ...student,
            users: user
        };

        res.json(combinedData);
    } catch (error) {
        console.error('Get student profile error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Update Student Profile
app.put('/api/student/profile', verifyToken, async (req, res) => {
    try {
        const updates = req.body;

        // Update students table
        const { data: student, error: studentError } = await supabase
            .from('students')
            .update(updates)
            .eq('id', req.userId)
            .select();

        if (studentError) throw studentError;

        // Update users table if name is provided
        if (updates.name) {
            const { error: userError } = await supabase
                .from('users')
                .update({ name: updates.name })
                .eq('id', req.userId);

            if (userError) throw userError;
        }

        res.json({
            message: 'Profile updated successfully',
            student: student[0]
        });
    } catch (error) {
        console.error('Update student profile error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Update Student Counselling Form
app.put('/api/student/counselling-form', verifyToken, async (req, res) => {
    try {
        const updates = req.body;

        // Map form field names to database column names if needed
        const dbUpdates = {
            aadhar_number: updates.aadhar_number,
            place: updates.place,
            district: updates.district,
            state: updates.state,
            pincode: updates.pincode,
            mobile: updates.mobile,
            father_name: updates.father_name,
            mother_name: updates.mother_name,
            father_mobile: updates.father_mobile,
            mother_mobile: updates.mother_mobile,
            father_occupation: updates.father_occupation,
            mother_occupation: updates.mother_occupation,
            address: updates.address,
            residence: updates.residence,
            hostel_name: updates.hostel_name,
            hostel_admission_date: updates.hostel_admission_date,
            hostel_fee: updates.hostel_fee ? parseFloat(updates.hostel_fee) : null,
            hostel_balance: updates.hostel_balance ? parseFloat(updates.hostel_balance) : null,
            is_hosteller: updates.residence === 'Hosteller',
            is_dayscholar: updates.residence === 'Day Scholar',
            bus_no: updates.bus_no,
            bus_route: updates.bus_route,
            bus_fee: updates.bus_fee ? parseFloat(updates.bus_fee) : null,
            bus_balance: updates.bus_balance ? parseFloat(updates.bus_balance) : null,
            tuition_fee: updates.tuition_fee ? parseFloat(updates.tuition_fee) : null,
            tuition_rtf: updates.tuition_rtf ? parseFloat(updates.tuition_rtf) : null,
            tuition_mq: updates.tuition_mq ? parseFloat(updates.tuition_mq) : null,
            tuition_nrtf: updates.tuition_nrtf ? parseFloat(updates.tuition_nrtf) : null,
            concession: updates.concession ? parseFloat(updates.concession) : null,
            balance_fee: updates.balance_fee ? parseFloat(updates.balance_fee) : null,
            semester: updates.semester ? parseInt(updates.semester) : null,
            year: updates.year ? parseInt(updates.year) : null,
            branch: updates.branch,
            section: updates.section,
            csp_project_title: updates.csp_project || updates.csp_project_title,
            project_guide: updates.guide || updates.project_guide,
            internship_details: updates.internship || updates.internship_details,
            moocs_courses: updates.moocs || updates.moocs_courses ? (Array.isArray(updates.moocs || updates.moocs_courses) ? updates.moocs || updates.moocs_courses : [updates.moocs || updates.moocs_courses]) : [],
            extra_activities: updates.extra_activities || [],
            remarks: updates.remarks,
            attendance_percentage: updates.attendance_percentage ? parseFloat(updates.attendance_percentage) : null
        };

        // Remove undefined values
        Object.keys(dbUpdates).forEach(key => {
            if (dbUpdates[key] === undefined) {
                delete dbUpdates[key];
            }
        });

        // Update students table
        const { data: student, error: studentError } = await supabase
            .from('students')
            .update(dbUpdates)
            .eq('id', req.userId)
            .select();

        if (studentError) throw studentError;

        res.json({
            message: 'Counselling form saved successfully',
            student: student[0]
        });
    } catch (error) {
        console.error('Update student counselling form error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Upload Profile Picture
app.post('/api/student/profile-picture', verifyToken, upload.single('photo'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file provided' });
        }

        // Convert image to base64
        const imageBase64 = req.file.buffer.toString('base64');
        const imageDataUrl = `data:${req.file.mimetype};base64,${imageBase64}`;

        // Update user profile image
        const { error } = await supabase
            .from('users')
            .update({ profile_image: imageDataUrl })
            .eq('id', req.userId);

        if (error) throw error;

        res.json({ message: 'Profile picture updated successfully' });
    } catch (error) {
        console.error('Profile picture upload error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get Counselling Records for Student
app.get('/api/student/counselling-records', verifyToken, async (req, res) => {
    try {
        const { data: records, error } = await supabase
            .from('counselling_records')
            .select('*')
            .eq('student_id', req.userId)
            .order('counselling_date', { ascending: false });

        if (error) throw error;

        res.json(records || []);
    } catch (error) {
        console.error('Get counselling records error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get Available Counsellors for a specific class (filtered by year, semester, branch, section)
app.get('/api/student/available-counsellors', verifyToken, async (req, res) => {
    try {
        const { year, semester, branch, section } = req.query;

        if (!year || !semester || !branch || !section) {
            return res.status(400).json({ error: 'Year, semester, branch, and section are required' });
        }

        // Find all counsellors that have an assignment matching the criteria
        const { data: counsellors, error: counsellorError } = await supabase
            .from('counsellors')
            .select('*');

        if (counsellorError) throw counsellorError;

        // Filter counsellors with matching assignments
        let matchingCounsellors = [];

        for (const counsellor of counsellors) {
            if (counsellor.assignments && Array.isArray(counsellor.assignments)) {
                // Check if any assignment matches the criteria
                const matchingAssignment = counsellor.assignments.find(a =>
                    a.assigned_year === parseInt(year) &&
                    a.assigned_semester === parseInt(semester) &&
                    a.assigned_branch === branch &&
                    a.assigned_section === section
                );

                if (matchingAssignment) {
                    // Count students assigned to this counsellor for this specific class
                    const { count: studentCount, error: countError } = await supabase
                        .from('students')
                        .select('id', { count: 'exact' })
                        .eq('counsellor_id', counsellor.id)
                        .eq('year', parseInt(year))
                        .eq('semester', parseInt(semester))
                        .eq('branch', branch)
                        .eq('section', section);

                    const currentStudents = countError ? 0 : (studentCount || 0);

                    // Fetch user data
                    const { data: user } = await supabase
                        .from('users')
                        .select('id, name, email')
                        .eq('id', counsellor.id)
                        .single();

                    matchingCounsellors.push({
                        ...counsellor,
                        users: user,
                        current_students: currentStudents,
                        max_students: matchingAssignment.max_students || 30
                    });
                }
            }
        }

        res.json(matchingCounsellors);
    } catch (error) {
        console.error('Get available counsellors error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Update Student Semester and Assign Counsellor
app.post('/api/student/update-semester', verifyToken, async (req, res) => {
    try {
        const { year, semester, branch, section, counsellor_id } = req.body;

        if (!year || !semester || !branch || !section || !counsellor_id) {
            return res.status(400).json({ error: 'Year, semester, branch, section, and counsellor_id are required' });
        }

        // Update student record with new semester/year/branch/section and counsellor assignment
        const { error: updateError } = await supabase
            .from('students')
            .update({
                year: parseInt(year),
                semester: parseInt(semester),
                branch: branch,
                section: section,
                counsellor_id: counsellor_id
            })
            .eq('id', req.userId);

        if (updateError) throw updateError;

        res.json({ message: 'Semester and counsellor updated successfully' });
    } catch (error) {
        console.error('Update semester error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get Assigned Counsellors
app.get('/api/student/counsellors', verifyToken, async (req, res) => {
    try {
        const { data: student, error: studentError } = await supabase
            .from('students')
            .select('counsellor_id')
            .eq('id', req.userId)
            .single();

        if (studentError) throw studentError;

        if (!student.counsellor_id) {
            return res.json([]);
        }

        const { data: counsellors, error } = await supabase
            .from('counsellors')
            .select('*')
            .eq('id', student.counsellor_id);

        if (error) throw error;

        // Fetch user data for each counsellor
        const counsellorsWithUsers = await Promise.all(
            counsellors.map(async (counsellor) => {
                const { data: user } = await supabase
                    .from('users')
                    .select('id, name, email')
                    .eq('id', counsellor.id)
                    .single();
                return { ...counsellor, users: user };
            })
        );

        res.json(counsellorsWithUsers);
    } catch (error) {
        console.error('Get counsellors error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ===========================
// COUNSELLOR ROUTES
// ===========================

// Get Counsellor Profile
app.get('/api/counsellor/profile', verifyToken, async (req, res) => {
    try {
        const { data: counsellor, error } = await supabase
            .from('counsellors')
            .select('*')
            .eq('id', req.userId)
            .single();

        if (error) throw error;

        if (!counsellor) {
            return res.status(404).json({ error: 'Counsellor not found' });
        }

        // Fetch user data
        const { data: user } = await supabase
            .from('users')
            .select('id, name, email')
            .eq('id', counsellor.id)
            .single();

        // Count total students assigned to this counsellor
        const { count: totalStudentCount, error: totalCountError } = await supabase
            .from('students')
            .select('id', { count: 'exact' })
            .eq('counsellor_id', counsellor.id);

        const totalStudents = totalCountError ? 0 : (totalStudentCount || 0);

        // Count students per assignment
        let assignmentCounts = [];
        if (counsellor.assignments && counsellor.assignments.length > 0) {
            assignmentCounts = await Promise.all(
                counsellor.assignments.map(async (assignment) => {
                    const { count: assignmentStudentCount, error: assignmentCountError } = await supabase
                        .from('students')
                        .select('id', { count: 'exact' })
                        .eq('counsellor_id', counsellor.id)
                        .eq('year', assignment.assigned_year)
                        .eq('semester', assignment.assigned_semester)
                        .eq('branch', assignment.assigned_branch)
                        .eq('section', assignment.assigned_section);

                    return assignmentCountError ? 0 : (assignmentStudentCount || 0);
                })
            );
        }

        res.json({
            ...counsellor,
            users: user,
            name: user?.name,
            counsellor_id: counsellor.counsellor_id,
            total_students: totalStudents,
            assignment_counts: assignmentCounts,
            current_students: totalStudents
        });
    } catch (error) {
        console.error('Get counsellor profile error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get Assigned Students
app.get('/api/counsellor/students', verifyToken, async (req, res) => {
    try {
        const { data: students, error } = await supabase
            .from('students')
            .select('*')
            .eq('counsellor_id', req.userId);

        if (error) throw error;

        // Fetch user data for each student
        const studentsWithUsers = await Promise.all(
            students.map(async (student) => {
                const { data: user } = await supabase
                    .from('users')
                    .select('id, name, email, profile_image')
                    .eq('id', student.id)
                    .single();
                return { ...student, users: user };
            })
        );

        res.json(studentsWithUsers);
    } catch (error) {
        console.error('Get students error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Unassign Student from Counsellor
app.post('/api/counsellor/students/:id/unassign', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;

        // Verify the student is assigned to this counsellor
        const { data: student, error: checkError } = await supabase
            .from('students')
            .select('counsellor_id')
            .eq('id', id)
            .single();

        if (checkError) throw checkError;

        // Check if student is assigned to the current counsellor
        if (student.counsellor_id !== req.userId) {
            return res.status(403).json({ error: 'You can only unassign students assigned to you' });
        }

        // Unassign the student by setting counsellor_id to null
        const { error: updateError } = await supabase
            .from('students')
            .update({ counsellor_id: null })
            .eq('id', id);

        if (updateError) throw updateError;

        res.json({ message: 'Student unassigned successfully' });
    } catch (error) {
        console.error('Unassign student error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get Student Details
app.get('/api/counsellor/student/:id', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;

        const { data: student, error: studentError } = await supabase
            .from('students')
            .select('*')
            .eq('id', id)
            .single();

        if (studentError) throw studentError;

        // Fetch user data separately
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('id, name, email, profile_image')
            .eq('id', id)
            .single();

        if (userError) throw userError;

        const { data: records, error: recordsError } = await supabase
            .from('counselling_records')
            .select('*')
            .eq('student_id', id);

        if (recordsError) throw recordsError;

        res.json({
            ...student,
            users: user,
            counselling_records: records
        });
    } catch (error) {
        console.error('Get student details error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Update Student (by Counsellor)
app.put('/api/counsellor/student/:id', verifyToken, async (req, res) => {
    try {
        if (req.userRole !== 'counsellor') {
            return res.status(403).json({ error: 'Only counsellors can update student data' });
        }

        const { id } = req.params;
        const updates = req.body || {};

        // Verify the counsellor is assigned to this student
        const { data: existingStudent, error: existingError } = await supabase
            .from('students')
            .select('counsellor_id')
            .eq('id', id)
            .single();

        if (existingError) throw existingError;

        if (existingStudent?.counsellor_id !== req.userId) {
            return res.status(403).json({ error: 'You are not assigned to this student' });
        }

        // Build objects for backlogs and attendance from flat keys (e.g. backlogs_I_semI, attendance_I_semI)
        const backlogsObj = {}
        const attendanceObj = {}

        Object.keys(updates).forEach(k => {
            if (k.startsWith('backlogs_')) {
                backlogsObj[k] = updates[k]
                delete updates[k]
            }
            if (k.startsWith('attendance_')) {
                attendanceObj[k] = updates[k]
                delete updates[k]
            }
        })

        // Map incoming fields to DB columns similar to counselling form update
        const dbUpdates = {
            aadhar_number: updates.aadhar_number,
            place: updates.place,
            district: updates.district,
            state: updates.state,
            pincode: updates.pincode,
            mobile: updates.mobile,
            father_name: updates.father_name,
            mother_name: updates.mother_name,
            father_mobile: updates.father_mobile,
            mother_mobile: updates.mother_mobile,
            father_occupation: updates.father_occupation,
            mother_occupation: updates.mother_occupation,
            address: updates.address,
            residence: updates.residence,
            hostel_name: updates.hostel_name,
            hostel_admission_date: updates.hostel_admission_date,
            hostel_fee: updates.hostel_fee ? parseFloat(updates.hostel_fee) : null,
            hostel_balance: updates.hostel_balance ? parseFloat(updates.hostel_balance) : null,
            is_hosteller: updates.residence === 'hosteller',
            is_dayscholar: updates.residence === 'dayscholar',
            bus_no: updates.bus_no,
            bus_route: updates.bus_route,
            bus_fee: updates.bus_fee ? parseFloat(updates.bus_fee) : null,
            bus_balance: updates.bus_balance ? parseFloat(updates.bus_balance) : null,
            tuition_fee: updates.tuition_fee ? parseFloat(updates.tuition_fee) : null,
            tuition_rtf: updates.tuition_rtf ? parseFloat(updates.tuition_rtf) : null,
            tuition_mq: updates.tuition_mq ? parseFloat(updates.tuition_mq) : null,
            tuition_nrtf: updates.tuition_nrtf ? parseFloat(updates.tuition_nrtf) : null,
            concession: updates.concession ? parseFloat(updates.concession) : null,
            balance_fee: updates.balance_fee ? parseFloat(updates.balance_fee) : null,
            semester: updates.semester ? parseInt(updates.semester) : null,
            year: updates.year ? parseInt(updates.year) : null,
            branch: updates.branch,
            section: updates.section,
            csp_project_title: updates.csp_project || updates.csp_project_title,
            project_guide: updates.guide || updates.project_guide,
            internship_details: updates.internship || updates.internship_details,
            moocs_courses: updates.moocs || updates.moocs_courses ? (Array.isArray(updates.moocs || updates.moocs_courses) ? updates.moocs || updates.moocs_courses : [updates.moocs || updates.moocs_courses]) : [],
            extra_activities: updates.extra_activities || [],
            remarks: updates.remarks,
            attendance_percentage: updates.attendance_percentage ? parseFloat(updates.attendance_percentage) : null,
            aoi: updates.aoi,
            backlogs_data: Object.keys(backlogsObj).length ? backlogsObj : (updates.backlogs_data || updates.backlogs || null),
            attendance_data: Object.keys(attendanceObj).length ? attendanceObj : (updates.attendance_data || null)
        };

        // Remove undefined values
        Object.keys(dbUpdates).forEach(key => {
            if (dbUpdates[key] === undefined) {
                delete dbUpdates[key];
            }
        });

        // Update students table
        const { data: student, error: studentError } = await supabase
            .from('students')
            .update(dbUpdates)
            .eq('id', id)
            .select();

        if (studentError) throw studentError;

        // Update user's name if provided
        if (updates.name) {
            const { error: userError } = await supabase
                .from('users')
                .update({ name: updates.name })
                .eq('id', id);

            if (userError) throw userError;
        }

        // Fetch updated user info to return combined object (keeps UI consistent)
        const { data: user, error: userFetchError } = await supabase
            .from('users')
            .select('id, name, email, profile_image')
            .eq('id', id)
            .single();

        if (userFetchError) {
            console.error('Failed to fetch user after student update:', userFetchError);
        }

        res.json({ ...student[0], users: user });
    } catch (error) {
        console.error('Update student by counsellor error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Create Counselling Record
app.post('/api/counsellor/counselling-record', verifyToken, async (req, res) => {
    try {
        let { student_id, semester, backlogs, moocs_courses, extra_activities, remarks, csp_project_title, project_guide, internship_details, counselling_date } = req.body;

        // student_id is required
        if (!student_id) {
            return res.status(400).json({ error: 'student_id is required' });
        }

        // Verify counsellor is assigned to this student
        const { data: studentRow, error: studentRowError } = await supabase
            .from('students')
            .select('counsellor_id, semester')
            .eq('id', student_id)
            .single();

        if (studentRowError) throw studentRowError;

        if (studentRow.counsellor_id !== req.userId) {
            return res.status(403).json({ error: 'You are not assigned to this student' });
        }

        // If semester missing, use student's current semester
        if (!semester && studentRow.semester) {
            semester = studentRow.semester;
        }

        // Ensure semester is an integer and not null
        const semInt = semester ? parseInt(semester) : null;
        if (!semInt) {
            return res.status(400).json({ error: 'Semester is required and must be a valid number' });
        }

        // Default counselling_date to now if not provided
        if (!counselling_date) counselling_date = new Date().toISOString();

        const { data: record, error } = await supabase
            .from('counselling_records')
            .insert([{
                student_id,
                counsellor_id: req.userId,
                semester: semInt,
                counselling_date,
                backlogs: backlogs || [],
                moocs_courses: moocs_courses || [],
                extra_activities: extra_activities || [],
                remarks,
                csp_project_title,
                project_guide,
                internship_details
            }])
            .select();

        if (error) throw error;

        res.status(201).json({
            message: 'Counselling record created successfully',
            record: record[0]
        });
    } catch (error) {
        console.error('Create counselling record error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get Counselling Records for a student (Counsellor view)
app.get('/api/counsellor/counselling-records', verifyToken, async (req, res) => {
    try {
        if (req.userRole !== 'counsellor') {
            return res.status(403).json({ error: 'Only counsellors can access these records' });
        }

        const { student_id } = req.query;
        if (!student_id) {
            return res.status(400).json({ error: 'student_id is required' });
        }

        // Verify counsellor is assigned to this student
        const { data: student, error: studentError } = await supabase
            .from('students')
            .select('counsellor_id')
            .eq('id', student_id)
            .single();

        if (studentError) throw studentError;

        if (student.counsellor_id !== req.userId) {
            return res.status(403).json({ error: 'You are not assigned to this student' });
        }

        const { data: records, error } = await supabase
            .from('counselling_records')
            .select('*')
            .eq('student_id', student_id)
            .order('counselling_date', { ascending: false });

        if (error) throw error;

        res.json(records || []);
    } catch (error) {
        console.error('Get counsellor counselling records error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ===========================
// ADMIN ROUTES
// ===========================

// Dashboard stats (counts + recent activity)
app.get('/api/admin/dashboard-stats', verifyToken, async (req, res) => {
    try {
        if (req.userRole !== 'admin') {
            return res.status(403).json({ error: 'Only admins can access this' });
        }

        // Total students (count from users table)
        const { data: studentCountData, error: studentCountError, count: studentCount } = await supabase
            .from('users')
            .select('id', { count: 'exact' })
            .eq('role', 'student');

        if (studentCountError) throw studentCountError;

        // Total counsellors
        const { data: counsellorCountData, error: counsellorCountError, count: counsellorCount } = await supabase
            .from('users')
            .select('id', { count: 'exact' })
            .eq('role', 'counsellor');

        if (counsellorCountError) throw counsellorCountError;

        // Recent student registrations (latest 5 users with role=student)
        const { data: recentUsers, error: recentUsersError } = await supabase
            .from('users')
            .select('id, name, email, created_at')
            .eq('role', 'student')
            .order('created_at', { ascending: false })
            .limit(5);

        if (recentUsersError) throw recentUsersError;

        // Attach student profile (roll_no) where available
        const recentStudents = await Promise.all((recentUsers || []).map(async (u) => {
            const { data: studentRow } = await supabase
                .from('students')
                .select('roll_no')
                .eq('id', u.id)
                .single();
            return { ...(studentRow || {}), users: u };
        }));

        // Recent counselling sessions (latest 5)
        const { data: recentSessionsData, error: recentSessionsError } = await supabase
            .from('counselling_records')
            .select('*')
            .order('counselling_date', { ascending: false })
            .limit(5);

        if (recentSessionsError) throw recentSessionsError;

        const recentSessions = await Promise.all((recentSessionsData || []).map(async (rec) => {
            const { data: studentUser } = await supabase
                .from('users')
                .select('id, name, email')
                .eq('id', rec.student_id)
                .single();

            const { data: counsellorUser } = await supabase
                .from('users')
                .select('id, name, email')
                .eq('id', rec.counsellor_id)
                .single();

            return {
                ...rec,
                students: { users: studentUser },
                counsellors: { users: counsellorUser }
            };
        }));

        res.json({
            totalStudents: studentCount || (studentCountData ? studentCountData.length : 0),
            totalCounsellors: counsellorCount || (counsellorCountData ? counsellorCountData.length : 0),
            recentStudents,
            recentSessions
        });
    } catch (error) {
        console.error('Get dashboard stats error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get Admin Profile
app.get('/api/admin/profile', verifyToken, async (req, res) => {
    try {
        if (req.userRole !== 'admin') {
            return res.status(403).json({ error: 'Only admins can access this' });
        }

        const { data: user, error } = await supabase
            .from('users')
            .select('id, name, email, role')
            .eq('id', req.userId)
            .single();

        if (error) throw error;

        res.json(user);
    } catch (error) {
        console.error('Get admin profile error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get All Students
app.get('/api/admin/students', verifyToken, async (req, res) => {
    try {
        if (req.userRole !== 'admin') {
            return res.status(403).json({ error: 'Only admins can access this' });
        }

        const page = req.query.page || 1;
        const limit = req.query.limit || 20;
        const offset = (page - 1) * limit;

        const { data: students, error: studentError, count } = await supabase
            .from('students')
            .select('*', { count: 'exact' })
            .range(offset, offset + limit - 1);

        if (studentError) throw studentError;

        // Fetch user data for each student
        const studentsWithUsers = await Promise.all(
            students.map(async (student) => {
                const { data: user } = await supabase
                    .from('users')
                    .select('id, name, email, profile_image')
                    .eq('id', student.id)
                    .single();
                return { ...student, users: user };
            })
        );

        res.json({
            students: studentsWithUsers,
            pagination: {
                page,
                limit,
                total: count,
                totalPages: Math.ceil(count / limit)
            }
        });
    } catch (error) {
        console.error('Get students error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get All Counsellors
app.get('/api/admin/counsellors', verifyToken, async (req, res) => {
    try {
        if (req.userRole !== 'admin') {
            return res.status(403).json({ error: 'Only admins can access this' });
        }

        const { data: counsellors, error } = await supabase
            .from('counsellors')
            .select('*');

        if (error) throw error;

        // Fetch user data and count assigned students per assignment for each counsellor
        const counsellorsWithUsers = await Promise.all(
            counsellors.map(async (counsellor) => {
                const { data: user } = await supabase
                    .from('users')
                    .select('id, name, email')
                    .eq('id', counsellor.id)
                    .single();

                // Count total students assigned to this counsellor
                const { count: totalStudentCount, error: totalCountError } = await supabase
                    .from('students')
                    .select('id', { count: 'exact' })
                    .eq('counsellor_id', counsellor.id);

                const totalStudents = totalCountError ? 0 : (totalStudentCount || 0);

                // Count students per assignment
                let assignmentCounts = [];
                if (counsellor.assignments && counsellor.assignments.length > 0) {
                    assignmentCounts = await Promise.all(
                        counsellor.assignments.map(async (assignment) => {
                            const { count: assignmentStudentCount, error: assignmentCountError } = await supabase
                                .from('students')
                                .select('id', { count: 'exact' })
                                .eq('counsellor_id', counsellor.id)
                                .eq('year', assignment.assigned_year)
                                .eq('semester', assignment.assigned_semester)
                                .eq('branch', assignment.assigned_branch)
                                .eq('section', assignment.assigned_section);

                            return assignmentCountError ? 0 : (assignmentStudentCount || 0);
                        })
                    );
                }

                return {
                    ...counsellor,
                    users: user,
                    total_students: totalStudents,
                    assignment_counts: assignmentCounts
                };
            })
        );

        res.json(counsellorsWithUsers);
    } catch (error) {
        console.error('Get counsellors error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get a Single Counsellor (admin only)
app.get('/api/admin/counsellor/:id', verifyToken, async (req, res) => {
    try {
        if (req.userRole !== 'admin') {
            return res.status(403).json({ error: 'Only admins can access this' });
        }

        const { id } = req.params;

        const { data: counsellor, error } = await supabase
            .from('counsellors')
            .select('*')
            .eq('id', id)
            .single();

        if (error) throw error;

        if (!counsellor) {
            return res.status(404).json({ error: 'Counsellor not found' });
        }

        // Fetch user data
        const { data: user } = await supabase
            .from('users')
            .select('id, name, email')
            .eq('id', counsellor.id)
            .single();

        // Count total students assigned to this counsellor
        const { count: totalStudentCount, error: totalCountError } = await supabase
            .from('students')
            .select('id', { count: 'exact' })
            .eq('counsellor_id', counsellor.id);

        const totalStudents = totalCountError ? 0 : (totalStudentCount || 0);

        // Count students per assignment
        let assignmentCounts = [];
        if (counsellor.assignments && counsellor.assignments.length > 0) {
            assignmentCounts = await Promise.all(
                counsellor.assignments.map(async (assignment) => {
                    const { count: assignmentStudentCount, error: assignmentCountError } = await supabase
                        .from('students')
                        .select('id', { count: 'exact' })
                        .eq('counsellor_id', counsellor.id)
                        .eq('year', assignment.assigned_year)
                        .eq('semester', assignment.assigned_semester)
                        .eq('branch', assignment.assigned_branch)
                        .eq('section', assignment.assigned_section);

                    return assignmentCountError ? 0 : (assignmentStudentCount || 0);
                })
            );
        }

        res.json({
            ...counsellor,
            users: user,
            total_students: totalStudents,
            assignment_counts: assignmentCounts
        });
    } catch (error) {
        console.error('Get counsellor error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Update a Counsellor (admin only)
app.put('/api/admin/counsellor/:id', verifyToken, async (req, res) => {
    try {
        if (req.userRole !== 'admin') {
            return res.status(403).json({ error: 'Only admins can perform this action' });
        }

        const { id } = req.params;
        const { name, email, assignments } = req.body;

        // Update user data
        const { error: userError } = await supabase
            .from('users')
            .update({ name, email })
            .eq('id', id);

        if (userError) throw userError;

        // Use first assignment for backward compatibility with single assignment fields
        const firstAssignment = assignments && assignments.length > 0 ? assignments[0] : {};

        // Update counsellor data
        const { error: counsellorError } = await supabase
            .from('counsellors')
            .update({
                assigned_year: firstAssignment.assigned_year || 1,
                assigned_semester: firstAssignment.assigned_semester || 1,
                assigned_branch: firstAssignment.assigned_branch || '',
                assigned_section: firstAssignment.assigned_section || '',
                max_students: firstAssignment.max_students || 30,
                assignments: assignments || []
            })
            .eq('id', id);

        if (counsellorError) throw counsellorError;

        res.json({ message: 'Counsellor updated successfully' });
    } catch (error) {
        console.error('Update counsellor error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Delete a Counsellor (admin only)
app.delete('/api/admin/counsellor/:id', verifyToken, async (req, res) => {
    try {
        if (req.userRole !== 'admin') {
            return res.status(403).json({ error: 'Only admins can perform this action' });
        }

        const { id } = req.params;

        // Delete counselling records for the counsellor
        const { error: recordsError } = await supabase
            .from('counselling_records')
            .delete()
            .eq('counsellor_id', id);

        if (recordsError) throw recordsError;

        // Delete counsellor profile
        const { error: counsellorError } = await supabase
            .from('counsellors')
            .delete()
            .eq('id', id);

        if (counsellorError) throw counsellorError;

        // Delete user record
        const { error: userError } = await supabase
            .from('users')
            .delete()
            .eq('id', id);

        if (userError) throw userError;

        res.json({ message: 'Counsellor deleted successfully' });
    } catch (error) {
        console.error('Delete counsellor error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Delete a student (admin only)
app.delete('/api/admin/student/:id', verifyToken, async (req, res) => {
    try {
        if (req.userRole !== 'admin') {
            return res.status(403).json({ error: 'Only admins can perform this action' });
        }

        const { id } = req.params;

        // Delete counselling records for the student
        const { error: recordsError } = await supabase
            .from('counselling_records')
            .delete()
            .eq('student_id', id);

        if (recordsError) throw recordsError;

        // Delete student profile
        const { error: studentError } = await supabase
            .from('students')
            .delete()
            .eq('id', id);

        if (studentError) throw studentError;

        // Delete user record
        const { error: userError } = await supabase
            .from('users')
            .delete()
            .eq('id', id);

        if (userError) throw userError;

        res.json({ message: 'Student deleted successfully' });
    } catch (error) {
        console.error('Delete student error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get Admin Logs
app.get('/api/admin/logs', verifyToken, async (req, res) => {
    try {
        if (req.userRole !== 'admin') {
            return res.status(403).json({ error: 'Only admins can access this' });
        }

        const page = req.query.page || 1;
        const limit = req.query.limit || 50;
        const offset = (page - 1) * limit;

        // For now, returning sample logs structure
        // In production, you'd query an actual logs table
        res.json({
            logs: [
                {
                    id: 1,
                    action: 'LOGIN',
                    description: 'Admin logged in',
                    timestamp: new Date(),
                    user: 'admin@example.com'
                }
            ],
            pagination: {
                page,
                limit,
                total: 1,
                totalPages: 1
            }
        });
    } catch (error) {
        console.error('Get admin logs error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'Server is running' });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

module.exports = app;
