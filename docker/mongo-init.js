// MongoDB Initialization Script for OWASP Security Scanner
// This script runs when MongoDB container is first created

// Switch to the scanner database
db = db.getSiblingDB('owasp_scanner');

// Create collections with schema validation
db.createCollection('users', {
    validator: {
        $jsonSchema: {
            bsonType: 'object',
            required: ['email', 'username', 'hashed_password', 'role'],
            properties: {
                email: {
                    bsonType: 'string',
                    description: 'Email address - required'
                },
                username: {
                    bsonType: 'string',
                    description: 'Username - required'
                },
                hashed_password: {
                    bsonType: 'string',
                    description: 'Hashed password - required'
                },
                role: {
                    enum: ['owner', 'admin', 'user'],
                    description: 'User role - required'
                },
                is_active: {
                    bsonType: 'bool'
                }
            }
        }
    }
});

db.createCollection('projects');
db.createCollection('scans');
db.createCollection('findings');
db.createCollection('verifications');
db.createCollection('payloads');
db.createCollection('reports');
db.createCollection('audit_logs');
db.createCollection('sessions');

// Create indexes for better performance
db.users.createIndex({ email: 1 }, { unique: true });
db.users.createIndex({ username: 1 }, { unique: true });

db.projects.createIndex({ owner_id: 1 });
db.projects.createIndex({ domain: 1 });
db.projects.createIndex({ domain: 1, owner_id: 1 }, { unique: true });

db.scans.createIndex({ project_id: 1 });
db.scans.createIndex({ status: 1 });
db.scans.createIndex({ created_at: -1 });
db.scans.createIndex({ project_id: 1, status: 1 });

db.findings.createIndex({ scan_id: 1 });
db.findings.createIndex({ severity: 1 });
db.findings.createIndex({ wstg_id: 1 });
db.findings.createIndex({ scan_id: 1, severity: 1 });

db.verifications.createIndex({ project_id: 1 }, { unique: true });
db.verifications.createIndex({ token: 1 });
db.verifications.createIndex({ expires_at: 1 }, { expireAfterSeconds: 0 });

db.payloads.createIndex({ category: 1 });
db.payloads.createIndex({ type: 1 });
db.payloads.createIndex({ is_aggressive: 1 });
db.payloads.createIndex({ category: 1, type: 1 });

db.reports.createIndex({ scan_id: 1 });
db.reports.createIndex({ user_id: 1 });
db.reports.createIndex({ expires_at: 1 }, { expireAfterSeconds: 0 });

db.audit_logs.createIndex({ user_id: 1 });
db.audit_logs.createIndex({ action: 1 });
db.audit_logs.createIndex({ created_at: -1 });
db.audit_logs.createIndex({ user_id: 1, created_at: -1 });

db.sessions.createIndex({ user_id: 1 });
db.sessions.createIndex({ refresh_token: 1 }, { unique: true });
db.sessions.createIndex({ expires_at: 1 }, { expireAfterSeconds: 0 });

print('MongoDB initialization completed successfully!');
print('Collections and indexes created for OWASP Security Scanner.');