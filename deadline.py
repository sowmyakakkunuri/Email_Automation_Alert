from langchain_groq import ChatGroq
import os
import datetime
from langchain_core.prompts import ChatPromptTemplate
from dotenv import load_dotenv
load_dotenv() # take/load environment variables from .env.

os.environ["LANGCHAIN_TRACING_V2"] = "true"
os.environ["LANGCHAIN_API_KEY"] = os.getenv("LANGCHAIN_API_KEY")
groq_api_key = os.getenv("GROQ_API_KEY")


llm_client = ChatGroq(api_key=groq_api_key,model_name="llama3-8b-8192")

def start_fetching_deadline(email_list):
    processed_emails = process_emails_with_llm(email_list, llm_client)
    return processed_emails

def process_emails_with_llm(email_list, llm_client):
  
    date = datetime.datetime.now().strftime("%Y-%m-%d")
    print(date)
     # Create a ChatPromptTemplate to manage the prompt structure
    prompt_template = ChatPromptTemplate.from_messages(
        [
            ("system", "You are a helpful AI email alert and automation bot.Today is {date}. Your specialty is {specialty}."),
            ("user", (
                "For the email below, respond with any deadlines in this format:\n"
                "- Date: YYYY-MM-DD\n"
                "- Task: Brief task description\n"
                "- Urgency: High/Medium/Low (if applicable)\n\n"
                "Subject: {subject}\nBody: {body}"
            ))
        ]
    )
   

    chain = prompt_template | llm_client
   

    processed_emails = []

    for email in email_list:
        # Generate prompt by filling in the subject and body of each email
        llm_response = chain.invoke({'specialty': 'for every email in the list check for deadlines and format it based on user requirements.', 'subject': email['subject'], 'body': email['body'], 'date': date})
       

       #to get 
        response_text = llm_response.content if hasattr(llm_response, 'content') else str(llm_response)

        processed_emails.append({
            'id': email['id'],
            'subject': email['subject'],
            'deadlines': response_text
        })

    return processed_emails

