from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from datetime import datetime, timedelta
import jwt
import bcrypt
import uvicorn
from enum import Enum

# Configuration
SECRET_KEY = "your-secret-key-here"  # Change this in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI(
    title="Aila API",
    description="Backend API for Aila project management system",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    # allow any origin in production:
    allow_origins=["*"],  # Uncomment this line to allow all origins in production
    # allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],  # React dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Enums
class TaskStatus(str, Enum):
    NOT_STARTED = "Not Started"
    IN_PROGRESS = "In Progress"
    PENDING = "Pending"
    COMPLETED = "Completed"

class TaskPriority(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"

class ProjectStatus(str, Enum):
    ACTIVE = "Active"
    INACTIVE = "Inactive"
    COMPLETED = "Completed"
    REVIEW = "Review"

# Pydantic Models
class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: int
    email: str
    name: str
    role: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TaskCreate(BaseModel):
    title: str
    description: Optional[str] = None
    status: TaskStatus = TaskStatus.NOT_STARTED
    priority: TaskPriority = TaskPriority.MEDIUM
    due_date: Optional[datetime] = None
    assigned_to: Optional[int] = None

class TaskResponse(BaseModel):
    id: int
    title: str
    description: Optional[str]
    status: TaskStatus
    priority: TaskPriority
    due_date: Optional[datetime]
    assigned_to: Optional[int]
    created_at: datetime
    updated_at: datetime

class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None
    status: ProjectStatus = ProjectStatus.ACTIVE
    team_id: Optional[int] = None

class ProjectResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    status: ProjectStatus
    progress: int
    team: str
    created_at: datetime
    updated_at: datetime

class NotificationResponse(BaseModel):
    id: int
    message: str
    time: str
    unread: bool

# Mock Database (In production, use a real database like PostgreSQL)
fake_users_db = {
    "john@example.com": {
        "id": 1,
        "email": "john@example.com",
        "name": "John Doe",
        "role": "Administrator",
        "hashed_password": bcrypt.hashpw("password123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    },
    "admin@aila.com": {
        "id": 2,
        "email": "admin@aila.com",
        "name": "Admin User",
        "role": "Administrator",
        "hashed_password": bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    }
}

fake_tasks_db = [
    {
        "id": 1,
        "title": "Design Review",
        "description": "Review the new UI design mockups",
        "status": TaskStatus.IN_PROGRESS,
        "priority": TaskPriority.HIGH,
        "due_date": datetime(2025, 6, 25),
        "assigned_to": 1,
        "created_at": datetime.now(),
        "updated_at": datetime.now()
    },
    {
        "id": 2,
        "title": "Code Implementation",
        "description": "Implement the backend APIs",
        "status": TaskStatus.PENDING,
        "priority": TaskPriority.MEDIUM,
        "due_date": datetime(2025, 6, 28),
        "assigned_to": 1,
        "created_at": datetime.now(),
        "updated_at": datetime.now()
    },
    {
        "id": 3,
        "title": "Testing Phase",
        "description": "Conduct comprehensive testing",
        "status": TaskStatus.NOT_STARTED,
        "priority": TaskPriority.LOW,
        "due_date": datetime(2025, 7, 1),
        "assigned_to": 2,
        "created_at": datetime.now(),
        "updated_at": datetime.now()
    }
]

fake_projects_db = [
    {
        "id": 1,
        "name": "Web Platform",
        "description": "Main web application development",
        "status": ProjectStatus.ACTIVE,
        "progress": 75,
        "team": "Frontend Team",
        "created_at": datetime.now(),
        "updated_at": datetime.now()
    },
    {
        "id": 2,
        "name": "Mobile App",
        "description": "iOS and Android mobile applications",
        "status": ProjectStatus.ACTIVE,
        "progress": 45,
        "team": "Mobile Team",
        "created_at": datetime.now(),
        "updated_at": datetime.now()
    },
    {
        "id": 3,
        "name": "API Integration",
        "description": "Third-party API integrations",
        "status": ProjectStatus.REVIEW,
        "progress": 90,
        "team": "Backend Team",
        "created_at": datetime.now(),
        "updated_at": datetime.now()
    }
]

fake_notifications_db = [
    {
        "id": 1,
        "message": "New task assigned",
        "time": "2 min ago",
        "unread": True
    },
    {
        "id": 2,
        "message": "Project deadline approaching",
        "time": "1 hour ago",
        "unread": True
    },
    {
        "id": 3,
        "message": "Team meeting scheduled",
        "time": "3 hours ago",
        "unread": False
    }
]

# Utility functions
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return email
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

def get_current_user(email: str = Depends(verify_token)):
    user = fake_users_db.get(email)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return user

# API Routes
@app.get("/")
async def root():
    return {"message": "Welcome to Aila API"}

@app.post("/auth/login", response_model=Token)
async def login(user_login: UserLogin):
    user = fake_users_db.get(user_login.email)
    if not user or not bcrypt.checkpw(user_login.password.encode('utf-8'), user["hashed_password"].encode('utf-8')):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["email"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/auth/me", response_model=UserResponse)
async def read_users_me(current_user: dict = Depends(get_current_user)):
    return UserResponse(
        id=current_user["id"],
        email=current_user["email"],
        name=current_user["name"],
        role=current_user["role"]
    )

# Task endpoints
@app.get("/tasks", response_model=List[TaskResponse])
async def get_tasks(current_user: dict = Depends(get_current_user)):
    return fake_tasks_db

@app.post("/tasks", response_model=TaskResponse)
async def create_task(task: TaskCreate, current_user: dict = Depends(get_current_user)):
    new_task = {
        "id": len(fake_tasks_db) + 1,
        "title": task.title,
        "description": task.description,
        "status": task.status,
        "priority": task.priority,
        "due_date": task.due_date,
        "assigned_to": task.assigned_to or current_user["id"],
        "created_at": datetime.now(),
        "updated_at": datetime.now()
    }
    fake_tasks_db.append(new_task)
    return new_task

@app.get("/tasks/{task_id}", response_model=TaskResponse)
async def get_task(task_id: int, current_user: dict = Depends(get_current_user)):
    task = next((task for task in fake_tasks_db if task["id"] == task_id), None)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task

@app.put("/tasks/{task_id}", response_model=TaskResponse)
async def update_task(task_id: int, task_update: TaskCreate, current_user: dict = Depends(get_current_user)):
    task_index = next((i for i, task in enumerate(fake_tasks_db) if task["id"] == task_id), None)
    if task_index is None:
        raise HTTPException(status_code=404, detail="Task not found")
    
    fake_tasks_db[task_index].update({
        "title": task_update.title,
        "description": task_update.description,
        "status": task_update.status,
        "priority": task_update.priority,
        "due_date": task_update.due_date,
        "updated_at": datetime.now()
    })
    return fake_tasks_db[task_index]

@app.delete("/tasks/{task_id}")
async def delete_task(task_id: int, current_user: dict = Depends(get_current_user)):
    task_index = next((i for i, task in enumerate(fake_tasks_db) if task["id"] == task_id), None)
    if task_index is None:
        raise HTTPException(status_code=404, detail="Task not found")
    
    deleted_task = fake_tasks_db.pop(task_index)
    return {"message": "Task deleted successfully", "task": deleted_task}

# Project endpoints
@app.get("/projects", response_model=List[ProjectResponse])
async def get_projects(current_user: dict = Depends(get_current_user)):
    return fake_projects_db

@app.post("/projects", response_model=ProjectResponse)
async def create_project(project: ProjectCreate, current_user: dict = Depends(get_current_user)):
    new_project = {
        "id": len(fake_projects_db) + 1,
        "name": project.name,
        "description": project.description,
        "status": project.status,
        "progress": 0,
        "team": "Default Team",
        "created_at": datetime.now(),
        "updated_at": datetime.now()
    }
    fake_projects_db.append(new_project)
    return new_project

@app.get("/projects/{project_id}", response_model=ProjectResponse)
async def get_project(project_id: int, current_user: dict = Depends(get_current_user)):
    project = next((proj for proj in fake_projects_db if proj["id"] == project_id), None)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project

@app.put("/projects/{project_id}", response_model=ProjectResponse)
async def update_project(project_id: int, project_update: ProjectCreate, current_user: dict = Depends(get_current_user)):
    project_index = next((i for i, proj in enumerate(fake_projects_db) if proj["id"] == project_id), None)
    if project_index is None:
        raise HTTPException(status_code=404, detail="Project not found")
    
    fake_projects_db[project_index].update({
        "name": project_update.name,
        "description": project_update.description,
        "status": project_update.status,
        "updated_at": datetime.now()
    })
    return fake_projects_db[project_index]

@app.delete("/projects/{project_id}")
async def delete_project(project_id: int, current_user: dict = Depends(get_current_user)):
    project_index = next((i for i, proj in enumerate(fake_projects_db) if proj["id"] == project_id), None)
    if project_index is None:
        raise HTTPException(status_code=404, detail="Project not found")
    
    deleted_project = fake_projects_db.pop(project_index)
    return {"message": "Project deleted successfully", "project": deleted_project}

# Notification endpoints
@app.get("/notifications", response_model=List[NotificationResponse])
async def get_notifications(current_user: dict = Depends(get_current_user)):
    return fake_notifications_db

@app.put("/notifications/{notification_id}/read")
async def mark_notification_read(notification_id: int, current_user: dict = Depends(get_current_user)):
    notification = next((notif for notif in fake_notifications_db if notif["id"] == notification_id), None)
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")
    
    notification["unread"] = False
    return {"message": "Notification marked as read"}

# Dashboard stats endpoint
@app.get("/dashboard/stats")
async def get_dashboard_stats(current_user: dict = Depends(get_current_user)):
    total_projects = len(fake_projects_db)
    active_tasks = len([task for task in fake_tasks_db if task["status"] in [TaskStatus.IN_PROGRESS, TaskStatus.PENDING]])
    team_members = len(fake_users_db)
    
    # Calculate completion rate
    completed_tasks = len([task for task in fake_tasks_db if task["status"] == TaskStatus.COMPLETED])
    total_tasks = len(fake_tasks_db)
    completion_rate = int((completed_tasks / total_tasks * 100)) if total_tasks > 0 else 0
    
    return {
        "total_projects": total_projects,
        "active_tasks": active_tasks,
        "team_members": team_members,
        "completion_rate": completion_rate
    }

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now()}

#if __name__ == "__main__":
#    uvicorn.run(app, host="0.0.0.0", port=8000)