import sqlite3
import matplotlib.pyplot as plt
import io
import base64
from flask import Flask, render_template, g

# Initialize Flask app
app = Flask(__name__)

DATABASE = 'instance/database.db'

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

@app.route('/')
def index():
    # Fetch data from the database
    db = get_db()
    
    # Active scholars count
    scholars_query = "SELECT COUNT(*) FROM Scholar"
    active_scholars = db.execute(scholars_query).fetchone()[0]
    
    # Active supervisors count
    supervisors_query = "SELECT COUNT(*) FROM Supervisor"
    active_supervisors = db.execute(supervisors_query).fetchone()[0]
    
    # Active papers count
    papers_query = "SELECT COUNT(*) FROM Paper WHERE Status='Approved'"
    active_papers = db.execute(papers_query).fetchone()[0]

    # Departments distribution (Pie Chart)
    department_query = "SELECT Department, COUNT(*) FROM User WHERE User_Type='scholar' GROUP BY Department"
    departments = db.execute(department_query).fetchall()
    departments_names = [row['Department'] for row in departments]
    department_counts = [row[1] for row in departments]

    # Progress data (Bar Chart)
    progress_query = "SELECT Progress FROM Paper WHERE Status='Approved'"
    progress_data = db.execute(progress_query).fetchall()
    progress_values = [row[0] for row in progress_data]

    # Average progress
    avg_progress = sum(progress_values) / len(progress_values) if progress_values else 0

    # Create individual visualizations and save them to a buffer
    def create_image(plot_func):
        # Clear the previous plot to avoid overlap
        plt.clf()
        
        # Call the plot function to generate a new plot
        plot_func()
        
        # Save the plot to a buffer
        img = io.BytesIO()
        plt.tight_layout()
        plt.savefig(img, format='png')
        img.seek(0)
        
        # Return the base64-encoded image
        return base64.b64encode(img.getvalue()).decode()

    # Plot 1: Active scholars, supervisors, and papers
    def plot_active_scholars_supervisors_papers():
        plt.bar(['Scholars', 'Supervisors', 'Papers'], [active_scholars, active_supervisors, active_papers])
        plt.title('Active Scholars, Supervisors, and Papers')
        plt.ylabel('Count')

    plot_active_scholars_supervisors_papers_url = create_image(plot_active_scholars_supervisors_papers)

    # Plot 2: Department distribution (Pie Chart)
    def plot_departments():
        plt.pie(department_counts, labels=departments_names, autopct='%1.1f%%', startangle=90)
        plt.title('Scholars by Department')

    plot_departments_url = create_image(plot_departments)

    # Plot 3: Progress of Papers (Histogram)
    def plot_progress_of_papers():
        plt.hist(progress_values, bins=10, color='skyblue', edgecolor='black')
        plt.title('Progress of Papers')
        plt.xlabel('Progress')
        plt.ylabel('Frequency')

    plot_progress_of_papers_url = create_image(plot_progress_of_papers)

    # Plot 4: Average Progress
    def plot_average_progress():
        plt.bar(['Average Progress'], [avg_progress], color='green')
        plt.title('Average Progress of Papers')

    plot_average_progress_url = create_image(plot_average_progress)

    # Plot 5: Paper Status Distribution (Pie Chart)
    status_query = "SELECT Status, COUNT(*) FROM Paper GROUP BY Status"
    status_data = db.execute(status_query).fetchall()
    statuses = [row['Status'] for row in status_data]
    status_counts = [row[1] for row in status_data]

    def plot_status_distribution():
        plt.pie(status_counts, labels=statuses, autopct='%1.1f%%', startangle=90)
        plt.title('Paper Status Distribution')

    plot_status_distribution_url = create_image(plot_status_distribution)

    # Plot 6: Scholars per College (Bar Chart)
    college_query = "SELECT College, COUNT(*) FROM Scholar GROUP BY College"
    college_data = db.execute(college_query).fetchall()
    colleges = [row['College'] for row in college_data]
    college_counts = [row[1] for row in college_data]

    def plot_scholars_per_college():
        plt.bar(colleges, college_counts, color='orange')
        plt.title('Scholars per College')
        plt.xlabel('College')
        plt.ylabel('Number of Scholars')
        plt.xticks(rotation=45)

    plot_scholars_per_college_url = create_image(plot_scholars_per_college)

    # Return the individual plot URLs to the frontend
    return render_template('visualize.html', 
                           plot_active_scholars_supervisors_papers_url=plot_active_scholars_supervisors_papers_url,
                           plot_departments_url=plot_departments_url,
                           plot_progress_of_papers_url=plot_progress_of_papers_url,
                           plot_average_progress_url=plot_average_progress_url,
                           plot_status_distribution_url=plot_status_distribution_url,
                           plot_scholars_per_college_url=plot_scholars_per_college_url)

if __name__ == '__main__':
    app.run(debug=True)
