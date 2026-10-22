// Navigation
document.querySelectorAll('.nav-links a').forEach(link => {
    link.addEventListener('click', function(e) {
        e.preventDefault();
        
        // Remove active class from all links and sections
        document.querySelectorAll('.nav-links a').forEach(l => l.classList.remove('active'));
        document.querySelectorAll('.feature-section').forEach(s => s.classList.remove('active-section'));
        
        // Add active class to clicked link
        this.classList.add('active');
        
        // Show corresponding section
        const targetId = this.getAttribute('href').substring(1);
        document.getElementById(targetId).classList.add('active-section');
    });
});

// Helper Function for API Calls
async function fetchData(url, data) {
    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return await response.json();
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred while analyzing the data.');
        return null;
    }
}

// UI Update Helper
function updateResultUI(prefix, result) {
    const resultPanel = document.getElementById(`${prefix}-result`);
    const loadingSpinner = resultPanel.querySelector('.loading-spinner');
    const resultContent = resultPanel.querySelector('.result-content');
    
    // Hide loading, show content
    loadingSpinner.classList.add('hidden');
    resultContent.classList.remove('hidden');
    
    // Update Score Circle
    const scoreCircle = document.getElementById(`${prefix}-score-circle`);
    const scoreText = document.getElementById(`${prefix}-score-text`);
    const riskLabel = document.getElementById(`${prefix}-risk-label`);
    const scoreContainer = scoreCircle.closest('.score-container');
    
    // Reset classes
    scoreContainer.classList.remove('risk-safe', 'risk-suspicious', 'risk-dangerous');
    
    // Set score dasharray for animation (circumference is 100 based on SVG setup)
    setTimeout(() => {
        scoreCircle.setAttribute('stroke-dasharray', `${result.probability}, 100`);
    }, 100);
    
    // Animate text number
    animateValue(prefix, scoreText, 0, result.probability, 1000);
    
    // Set text and colors
    riskLabel.textContent = result.risk_level;
    const riskClass = result.risk_level.toLowerCase() === 'safe' ? 'risk-safe' : 
                      result.risk_level.toLowerCase() === 'suspicious' ? 'risk-suspicious' : 'risk-dangerous';
    scoreContainer.classList.add(riskClass);
    
    // Update Explanation and Patterns
    document.getElementById(`${prefix}-explanation`).textContent = result.explanation;
    
    const patternsList = document.getElementById(`${prefix}-patterns`);
    patternsList.innerHTML = '';
    result.patterns.forEach(pattern => {
        const li = document.createElement('li');
        li.textContent = pattern;
        patternsList.appendChild(li);
    });
}

let animationFrames = {};

function animateValue(prefix, obj, start, end, duration, appendPercent = true) {
    let startTimestamp = null;
    
    if (animationFrames[prefix]) {
        window.cancelAnimationFrame(animationFrames[prefix]);
    }
    
    const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        let val = Math.floor(progress * (end - start) + start);
        obj.innerHTML = appendPercent ? val + '%' : val.toLocaleString();
        
        if (progress < 1) {
            animationFrames[prefix] = window.requestAnimationFrame(step);
        } else {
            animationFrames[prefix] = null;
        }
    };
    animationFrames[prefix] = window.requestAnimationFrame(step);
}

// 1. Analyze Message
async function analyzeMessage() {
    const text = document.getElementById('message-input').value;
    if (!text) {
        alert("Please enter a message to analyze.");
        return;
    }
    
    // Show Loading UI
    const resultPanel = document.getElementById('message-result');
    resultPanel.classList.remove('hidden');
    resultPanel.querySelector('.loading-spinner').classList.remove('hidden');
    resultPanel.querySelector('.result-content').classList.add('hidden');
    
    // Simulate slight delay for effect
    setTimeout(async () => {
        const result = await fetchData('/api/analyze_message', { text });
        if (result) updateResultUI('message', result);
    }, 1500);
}

// 2. Analyze Job
async function analyzeJob() {
    const company = document.getElementById('job-company').value;
    const title = document.getElementById('job-title').value;
    const salary = document.getElementById('job-salary').value;
    const email = document.getElementById('job-email').value;
    const description = document.getElementById('job-desc').value;
    
    if (!description) {
        alert("Job description is required for analysis.");
        return;
    }
    
    const resultPanel = document.getElementById('job-result');
    resultPanel.classList.remove('hidden');
    resultPanel.querySelector('.loading-spinner').classList.remove('hidden');
    resultPanel.querySelector('.result-content').classList.add('hidden');
    
    setTimeout(async () => {
        const result = await fetchData('/api/analyze_job', { company, title, salary, email, description });
        if (result) updateResultUI('job', result);
    }, 1500);
}

// 3. Analyze Link
async function analyzeLink() {
    const url = document.getElementById('link-url').value;
    if (!url) {
        alert("Please enter a URL to analyze.");
        return;
    }
    
    const resultPanel = document.getElementById('link-result');
    resultPanel.classList.remove('hidden');
    resultPanel.querySelector('.loading-spinner').classList.remove('hidden');
    resultPanel.querySelector('.result-content').classList.add('hidden');
    
    setTimeout(async () => {
        const result = await fetchData('/api/analyze_link', { url });
        if (result) updateResultUI('link', result);
    }, 1500);
}

// --- Dashboard Mock Logic ---

function initDashboard() {
    // Animate stats
    animateValue('scans', document.getElementById('stat-scans'), 0, 14239, 2000, false);
    animateValue('blocked', document.getElementById('stat-blocked'), 0, 1452, 2000, false);
    animateValue('nodes', document.getElementById('stat-nodes'), 0, 142, 1500, false);

    // Initial mock feed items
    generateMockFeedItem();
    generateMockFeedItem();
    generateMockFeedItem();

    // Start interval for live feed
    setInterval(generateMockFeedItem, 3000);
}

const mockFeedEvents = [
    { text: "Blocked phishing attempt from IP 192.168.1.104", level: "alert-high" },
    { text: "Suspicious login pattern detected in Region EU-West", level: "alert-med" },
    { text: "New malware signature added to database", level: "alert-low" },
    { text: "Scam message filtered for User #4912", level: "alert-low" },
    { text: "Fake job posting flagged from domain career-update.xyz", level: "alert-high" },
    { text: "DDoS mitigation active on node Alpha-7", level: "alert-med" },
    { text: "AI heuristics updated successfully", level: "alert-low" }
];

function generateMockFeedItem() {
    const feedContainer = document.getElementById('activity-feed');
    if (!feedContainer) return;

    const event = mockFeedEvents[Math.floor(Math.random() * mockFeedEvents.length)];
    const now = new Date();
    const timeString = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    const item = document.createElement('div');
    item.className = `feed-item ${event.level}`;
    item.innerHTML = `<span class="time">[${timeString}]</span> ${event.text}`;

    feedContainer.prepend(item);

    // Keep only last 10 items
    if (feedContainer.children.length > 10) {
        feedContainer.removeChild(feedContainer.lastChild);
    }
}

// Initialize Dashboard when DOM loads
document.addEventListener('DOMContentLoaded', () => {
    if (document.getElementById('dashboard')) {
        initDashboard();
    }
});
