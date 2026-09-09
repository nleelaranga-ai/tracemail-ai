import os
from groq import Groq


def generate_explanation(email_body, score, entities):
    api_key = os.getenv("GROQ_API_KEY")

    if not api_key:
        return "LLM explanation unavailable. GROQ_API_KEY is not configured."

    client = Groq(api_key=api_key)

    prompt = f"""
Analyze this email for phishing.

Phishing score: {score}/100

Entities:
{entities}

Email:
{email_body[:3000]}

Give a short evidence-based explanation.
Only mention facts supported by the email, score, or entities.
Do not invent information.
"""

    response = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=0.2,
        max_tokens=150
    )

    return response.choices[0].message.content.strip()