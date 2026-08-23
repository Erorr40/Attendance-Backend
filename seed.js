import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config();

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/elswedy_attendance';

console.log('🌱 Starting Elswedy Attendance Database Seeder...');
console.log(`📡 Connecting to MongoDB URI: ${MONGODB_URI.replace(/:[^:@]+@/, ':****@')}`);

// Mongoose Schemas
const UserSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  email: { type: String, required: true },
  role: { type: String, required: true }, // 'hr_admin' | 'board' | 'employee'
  password: { type: String, required: true },
  departmentId: String,
  teacherId: String,
  avatar: String,
  phone: String,
  jobTitle: String,
  lastLogin: String,
  lastLoginIp: String,
});

const DepartmentSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  name: String,
  code: String,
  headTeacherId: String,
  headTeacherName: String,
  building: String,
  room: String,
  totalTeachers: Number,
});

const ScheduleSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  name: String,
  startTime: String,
  endTime: String,
  gracePeriodMinutes: Number,
  lateThresholdMinutes: Number,
  workingDays: [String],
  description: String,
});

const DeviceSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  name: String,
  deviceModel: String,
  location: String,
  status: String,
  ipAddress: String,
  macAddress: String,
  lastSync: String,
  registeredCount: Number,
  pendingEventsCount: Number,
  firmwareVersion: String,
  port: Number,
  isEntranceGate: Boolean,
});

const TeacherSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  employeeId: { type: String, required: true },
  fullName: { type: String, required: true },
  email: { type: String, required: true },
  phone: String,
  departmentId: String,
  departmentName: String,
  position: String,
  hireDate: String,
  scheduleId: String,
  accountStatus: String,
  fingerprintStatus: String,
  fingerprintRegisteredAt: String,
  fingerprintDeviceId: String,
  gender: String,
  username: String,
  password: String,
  plainPassword: String,
});

const AttendanceRecordSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  teacherId: String,
  teacherName: String,
  employeeId: String,
  departmentId: String,
  departmentName: String,
  date: String,
  scheduledStartTime: String,
  scheduledEndTime: String,
  checkInTime: String,
  checkOutTime: String,
  status: String,
  lateDurationMinutes: Number,
  earlyLeaveMinutes: Number,
  deviceId: String,
  deviceName: String,
  verificationMethod: String,
});

const LeaveRequestSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  teacherId: String,
  teacherName: String,
  employeeId: String,
  departmentId: String,
  departmentName: String,
  leaveType: String,
  startDate: String,
  endDate: String,
  daysCount: Number,
  reason: String,
  status: String,
  appliedAt: String,
});

const AuditLogSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  timestamp: String,
  action: String,
  entity: String,
  entityId: String,
  actorName: String,
  actorRole: String,
  details: String,
  ipAddress: String,
  category: String,
  severity: String,
});

const SystemLogSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  timestamp: String,
  level: String,
  component: String,
  message: String,
  details: String,
});

// Models
const User = mongoose.model('User', UserSchema);
const Department = mongoose.model('Department', DepartmentSchema);
const Schedule = mongoose.model('Schedule', ScheduleSchema);
const Device = mongoose.model('Device', DeviceSchema);
const Teacher = mongoose.model('Teacher', TeacherSchema);
const AttendanceRecord = mongoose.model('AttendanceRecord', AttendanceRecordSchema);
const LeaveRequest = mongoose.model('LeaveRequest', LeaveRequestSchema);
const AuditLog = mongoose.model('AuditLog', AuditLogSchema);
const SystemLog = mongoose.model('SystemLog', SystemLogSchema);

// Seed Data
const seedUsers = [
  {
    id: 'usr-hr',
    username: 'hr_admin',
    name: 'Mariam Soliman (HR Desk)',
    email: 'hr@elswedy-schools.edu.eg',
    role: 'hr_admin', // Full Access
    password: 'elswedy@2026',
    avatar: 'https://images.unsplash.com/photo-1573496359142-b8d87734a5a2?w=150&auto=format&fit=crop&q=80',
    phone: '+20 101 555 4433',
    jobTitle: 'Senior HR & Attendance Administrator',
    lastLogin: new Date().toISOString(),
    lastLoginIp: '192.168.10.12',
  },
  {
    id: 'usr-board',
    username: 'board',
    name: 'Eng. Ahmed Rafat (Board Executive)',
    email: 'board@elswedy-schools.edu.eg',
    role: 'board', // Read-Only Access, No Edits, No Passwords
    password: 'board@2026',
    avatar: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80',
    phone: '+20 100 999 8888',
    jobTitle: 'Board of Directors — Executive Observer',
    lastLogin: new Date().toISOString(),
    lastLoginIp: '192.168.10.2',
  },
  {
    id: 'usr-employee',
    username: 'employee',
    name: 'Eng. Ahmed Hassan (Faculty Employee)',
    email: 'employee@elswedy-schools.edu.eg',
    role: 'employee', // Employee Portal (Teacher Role)
    password: 'emp@2026',
    teacherId: 'tch-01',
    departmentId: 'dept-1',
    avatar: 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=150&auto=format&fit=crop&q=80',
    phone: '+20 100 458 9123',
    jobTitle: 'Lead Instructor & AI Specialist',
    lastLogin: new Date().toISOString(),
    lastLoginIp: '192.168.10.101',
  },
];

const seedDepartments = [
  {
    id: 'dept-1',
    name: 'Software Development & AI',
    code: 'SDAI',
    headTeacherId: 'tch-01',
    headTeacherName: 'Eng. Ahmed Hassan',
    building: 'Engineering Block A',
    room: 'Room 301 - AI Lab',
    totalTeachers: 10,
  },
  {
    id: 'dept-2',
    name: 'Networks & Cloud Infrastructure',
    code: 'NCI',
    headTeacherId: 'tch-02',
    headTeacherName: 'Dr. Mahmoud El-Sayed',
    building: 'Engineering Block A',
    room: 'Room 204 - Cisco Hub',
    totalTeachers: 8,
  },
  {
    id: 'dept-3',
    name: 'Industrial Automation & Robotics',
    code: 'IAR',
    headTeacherId: 'tch-03',
    headTeacherName: 'Eng. Tarek Mansour',
    building: 'Technology Workshop B',
    room: 'Hall 102 - Siemens PLC Lab',
    totalTeachers: 12,
  },
  {
    id: 'dept-4',
    name: 'Electrical Power & Maintenance',
    code: 'EPM',
    headTeacherId: 'tch-04',
    headTeacherName: 'Eng. Sara Al-Attar',
    building: 'Technology Workshop B',
    room: 'Lab 105 - High Voltage Lab',
    totalTeachers: 7,
  },
  {
    id: 'dept-5',
    name: 'Renewable & Solar Energy',
    code: 'RSE',
    headTeacherId: 'tch-05',
    headTeacherName: 'Eng. Khaled Ibrahim',
    building: 'Energy Complex C',
    room: 'Room 402 - Photovoltaic Lab',
    totalTeachers: 6,
  },
];

const seedSchedules = [
  {
    id: 'sch-standard',
    name: 'Standard Faculty Shift',
    startTime: '07:30',
    endTime: '15:00',
    gracePeriodMinutes: 10,
    lateThresholdMinutes: 40,
    workingDays: ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday'],
    description: 'Standard working schedule for technical faculty teachers and instructors',
  },
  {
    id: 'sch-admin',
    name: 'Administrative & Management Shift',
    startTime: '08:00',
    endTime: '16:00',
    gracePeriodMinutes: 15,
    lateThresholdMinutes: 30,
    workingDays: ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday'],
    description: 'Executive shift for department heads, HR, and administrative staff',
  },
];

const seedDevices = [
  {
    id: 'dev-gate-01',
    name: 'Gate 01 Main Turnstile Biometric Device',
    deviceModel: 'ZKTeco uFace800 Multi-Biometric',
    location: 'Campus Main Entrance Gate 01',
    status: 'ONLINE',
    ipAddress: '192.168.10.201',
    macAddress: '00:1A:2B:3C:4D:5E',
    lastSync: new Date().toISOString(),
    registeredCount: 43,
    pendingEventsCount: 0,
    firmwareVersion: 'v4.18.22',
    port: 4370,
    isEntranceGate: true,
  },
  {
    id: 'dev-gate-02',
    name: 'Gate 02 Workshop Wing Terminal',
    deviceModel: 'Hikvision DS-K1T671M Face & Fingerprint',
    location: 'Engineering Workshop Entrance Gate 02',
    status: 'ONLINE',
    ipAddress: '192.168.10.202',
    macAddress: '00:1A:2B:3C:4D:5F',
    lastSync: new Date().toISOString(),
    registeredCount: 38,
    pendingEventsCount: 0,
    firmwareVersion: 'v2.0.4',
    port: 4370,
    isEntranceGate: true,
  },
  {
    id: 'dev-gate-03',
    name: 'Gate 03 Administration Turnstile',
    deviceModel: 'ZKTeco F22 Ultra-Thin Terminal',
    location: 'Administration Building Gate 03',
    status: 'ONLINE',
    ipAddress: '192.168.10.203',
    macAddress: '00:1A:2B:3C:4D:60',
    lastSync: new Date().toISOString(),
    registeredCount: 15,
    pendingEventsCount: 0,
    firmwareVersion: 'v3.12.1',
    port: 4370,
    isEntranceGate: true,
  },
];

const seedTeachers = [
  {
    id: 'tch-01',
    employeeId: 'ELS-T-1001',
    fullName: 'Eng. Ahmed Hassan',
    email: 'ahmed.hassan@elswedy-schools.edu.eg',
    phone: '+20 100 458 9123',
    departmentId: 'dept-1',
    departmentName: 'Software Development & AI',
    position: 'Lead Instructor & AI Specialist',
    hireDate: '2021-09-01',
    scheduleId: 'sch-standard',
    accountStatus: 'Active',
    fingerprintStatus: 'Registered',
    fingerprintRegisteredAt: '2021-09-05T08:00:00Z',
    fingerprintDeviceId: 'dev-gate-01',
    gender: 'Male',
    username: 'ahmed.hassan',
    password: 'emp@2026',
    plainPassword: 'emp@2026',
  },
  {
    id: 'tch-02',
    employeeId: 'ELS-T-1002',
    fullName: 'Dr. Mahmoud El-Sayed',
    email: 'mahmoud.elsayed@elswedy-schools.edu.eg',
    phone: '+20 111 222 3344',
    departmentId: 'dept-2',
    departmentName: 'Networks & Cloud Infrastructure',
    position: 'Department Head & Cisco Fellow',
    hireDate: '2020-08-15',
    scheduleId: 'sch-admin',
    accountStatus: 'Active',
    fingerprintStatus: 'Registered',
    fingerprintRegisteredAt: '2020-08-18T08:00:00Z',
    fingerprintDeviceId: 'dev-gate-01',
    gender: 'Male',
    username: 'dr.mahmoud',
    password: 'cisco@2026',
    plainPassword: 'cisco@2026',
  },
  {
    id: 'tch-03',
    employeeId: 'ELS-T-1003',
    fullName: 'Eng. Tarek Mansour',
    email: 'tarek.mansour@elswedy-schools.edu.eg',
    phone: '+20 122 333 4455',
    departmentId: 'dept-3',
    departmentName: 'Industrial Automation & Robotics',
    position: 'PLC & Siemens Automation Specialist',
    hireDate: '2022-01-10',
    scheduleId: 'sch-standard',
    accountStatus: 'Active',
    fingerprintStatus: 'Registered',
    fingerprintRegisteredAt: '2022-01-12T08:00:00Z',
    fingerprintDeviceId: 'dev-gate-02',
    gender: 'Male',
    username: 'tarek.mansour',
    password: 'ELS#Mansour2026!',
    plainPassword: 'ELS#Mansour2026!',
  },
  {
    id: 'tch-04',
    employeeId: 'ELS-T-1004',
    fullName: 'Eng. Sara Al-Attar',
    email: 'sara.attar@elswedy-schools.edu.eg',
    phone: '+20 100 555 6677',
    departmentId: 'dept-4',
    departmentName: 'Electrical Power & Maintenance',
    position: 'Electrical Engineering Lecturer',
    hireDate: '2021-03-15',
    scheduleId: 'sch-standard',
    accountStatus: 'Active',
    fingerprintStatus: 'Registered',
    fingerprintRegisteredAt: '2021-03-20T08:00:00Z',
    fingerprintDeviceId: 'dev-gate-01',
    gender: 'Female',
    username: 'sara.attar',
    password: 'ELS#Attar2026!',
    plainPassword: 'ELS#Attar2026!',
  },
  {
    id: 'tch-05',
    employeeId: 'ELS-T-1005',
    fullName: 'Eng. Khaled Ibrahim',
    email: 'khaled.ibrahim@elswedy-schools.edu.eg',
    phone: '+20 115 666 7788',
    departmentId: 'dept-5',
    departmentName: 'Renewable & Solar Energy',
    position: 'Solar Energy Systems Instructor',
    hireDate: '2022-09-01',
    scheduleId: 'sch-standard',
    accountStatus: 'Active',
    fingerprintStatus: 'Registered',
    fingerprintRegisteredAt: '2022-09-05T08:00:00Z',
    fingerprintDeviceId: 'dev-gate-01',
    gender: 'Male',
    username: 'khaled.ibrahim',
    password: 'ELS#Ibrahim2026!',
    plainPassword: 'ELS#Ibrahim2026!',
  },
];

const todayDate = new Date().toISOString().split('T')[0];

const seedAttendance = [
  {
    id: `att-01-${todayDate}`,
    teacherId: 'tch-01',
    teacherName: 'Eng. Ahmed Hassan',
    employeeId: 'ELS-T-1001',
    departmentId: 'dept-1',
    departmentName: 'Software Development & AI',
    date: todayDate,
    scheduledStartTime: '07:30',
    scheduledEndTime: '15:00',
    checkInTime: '07:28 AM',
    checkOutTime: null,
    status: 'Present',
    lateDurationMinutes: 0,
    earlyLeaveMinutes: 0,
    deviceId: 'dev-gate-01',
    deviceName: 'Gate 01 Main Turnstile Biometric Device',
    verificationMethod: 'Fingerprint',
  },
  {
    id: `att-02-${todayDate}`,
    teacherId: 'tch-02',
    teacherName: 'Dr. Mahmoud El-Sayed',
    employeeId: 'ELS-T-1002',
    departmentId: 'dept-2',
    departmentName: 'Networks & Cloud Infrastructure',
    date: todayDate,
    scheduledStartTime: '08:00',
    scheduledEndTime: '16:00',
    checkInTime: '07:55 AM',
    checkOutTime: null,
    status: 'Present',
    lateDurationMinutes: 0,
    earlyLeaveMinutes: 0,
    deviceId: 'dev-gate-01',
    deviceName: 'Gate 01 Main Turnstile Biometric Device',
    verificationMethod: 'Fingerprint',
  },
  {
    id: `att-03-${todayDate}`,
    teacherId: 'tch-03',
    teacherName: 'Eng. Tarek Mansour',
    employeeId: 'ELS-T-1003',
    departmentId: 'dept-3',
    departmentName: 'Industrial Automation & Robotics',
    date: todayDate,
    scheduledStartTime: '07:30',
    scheduledEndTime: '15:00',
    checkInTime: '07:48 AM',
    checkOutTime: null,
    status: 'Late',
    lateDurationMinutes: 18,
    earlyLeaveMinutes: 0,
    deviceId: 'dev-gate-02',
    deviceName: 'Gate 02 Workshop Wing Terminal',
    verificationMethod: 'Fingerprint',
  },
];

const seedLeaves = [
  {
    id: 'leave-01',
    teacherId: 'tch-04',
    teacherName: 'Eng. Sara Al-Attar',
    employeeId: 'ELS-T-1004',
    departmentId: 'dept-4',
    departmentName: 'Electrical Power & Maintenance',
    leaveType: 'Annual Leave',
    startDate: todayDate,
    endDate: todayDate,
    daysCount: 1,
    reason: 'Family errand and personal appointment',
    status: 'APPROVED',
    appliedAt: new Date(Date.now() - 86400000).toISOString(),
  },
];

async function runSeed() {
  try {
    await mongoose.connect(MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
    console.log('✅ Successfully connected to MongoDB for seeding.');

    // Clear existing collections
    console.log('🧹 Cleaning existing collections...');
    await Promise.all([
      User.deleteMany({}),
      Department.deleteMany({}),
      Schedule.deleteMany({}),
      Device.deleteMany({}),
      Teacher.deleteMany({}),
      AttendanceRecord.deleteMany({}),
      LeaveRequest.deleteMany({}),
      AuditLog.deleteMany({}),
      SystemLog.deleteMany({}),
    ]);

    // Insert Seed Data
    console.log('📦 Inserting seed data...');
    await User.insertMany(seedUsers);
    await Department.insertMany(seedDepartments);
    await Schedule.insertMany(seedSchedules);
    await Device.insertMany(seedDevices);
    await Teacher.insertMany(seedTeachers);
    await AttendanceRecord.insertMany(seedAttendance);
    await LeaveRequest.insertMany(seedLeaves);

    console.log('\n=============================================================');
    console.log('🎉 ELSWEDY ATTENDANCE DATABASE SEEDED SUCCESSFULLY!');
    console.log('=============================================================');
    console.log('🔑 TEST ACCOUNTS CREATED FOR THE 3 ROLES:\n');
    console.log('1️⃣ HR ADMIN (Full Access):');
    console.log('   Username: hr_admin');
    console.log('   Password: elswedy@2026\n');

    console.log('2️⃣ BOARD MEMBER (Read-Only Access, Passwords Masked):');
    console.log('   Username: board');
    console.log('   Password: board@2026\n');

    console.log('3️⃣ EMPLOYEE (Faculty Personal Portal):');
    console.log('   Username: employee (or ahmed.hassan)');
    console.log('   Password: emp@2026\n');
    console.log('=============================================================\n');

    process.exit(0);
  } catch (error) {
    console.error('❌ Error seeding database:', error);
    process.exit(1);
  }
}

runSeed();
