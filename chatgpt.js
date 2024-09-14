const axios = require('axios');
require('dotenv').config()
const apiKey = process.env.OPENAI_API_KEY; 
console.log('API KEY');
console.log(apiKey);

async function getRecommendations(data) {
    return sendOpenAIRequest(data);
}

async function getTestCases(data) {
    return sendOpenAIRequest(data);
}

async function sendOpenAIRequest(data) {
    try {
        const response = await axios.post(
            'https://api.openai.com/v1/chat/completions',
            {
                model: data.model,
                messages: data.messages, // messages should be an array of objects
                max_tokens: data.max_tokens,
                temperature: 0.7, // Optional parameter to control randomness
                top_p: 1.0 // Optional parameter for nucleus sampling
            },
            {
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${apiKey}` // Use the correct API key here
                }
            }
        );
        console.log(response.data);
        return response.data.choices[0].message.content;
    } catch (error) {
        console.error('Error communicating with OpenAI API:', error.response ? error.response.data : error.message);
        return 'Error analyzing code';
    }
}

module.exports = {
    getRecommendations,
    getTestCases
};
