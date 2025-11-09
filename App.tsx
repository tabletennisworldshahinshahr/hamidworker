import React, { useState, useCallback } from 'react';
import { GoogleGenAI } from '@google/genai';

// --- UI Components ---

const Header = () => (
  <header className="text-center mb-8">
    <h1 className="text-4xl md:text-5xl font-extrabold text-gray-800 dark:text-white tracking-tight">
      AI Recipe Generator
    </h1>
    <p className="text-lg text-gray-500 dark:text-gray-400 mt-2">
      Turn your ingredients into delicious meals!
    </p>
  </header>
);

const IngredientInput = ({ ingredients, setIngredients, onSubmit, isLoading }) => (
  <div className="mb-6">
    <label htmlFor="ingredients" className="block mb-2 text-sm font-medium text-gray-700 dark:text-gray-300">
      Enter ingredients you have, separated by commas:
    </label>
    <textarea
      id="ingredients"
      rows={4}
      className="w-full p-4 text-gray-900 border border-gray-300 rounded-lg bg-gray-50 text-base focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500 transition-all duration-300"
      placeholder="e.g., chicken breast, tomatoes, rice, onion, garlic"
      value={ingredients}
      onChange={(e) => setIngredients(e.target.value)}
      disabled={isLoading}
      aria-label="Ingredients Input"
    />
    <button
      onClick={onSubmit}
      disabled={isLoading || !ingredients.trim()}
      className="mt-4 w-full inline-flex justify-center items-center px-5 py-3 text-base font-medium text-center text-white bg-blue-700 rounded-lg hover:bg-blue-800 focus:ring-4 focus:outline-none focus:ring-blue-300 disabled:bg-gray-400 dark:bg-blue-600 dark:hover:bg-blue-700 dark:focus:ring-blue-800 dark:disabled:bg-gray-600 transition-all duration-300 transform hover:scale-105 disabled:scale-100"
      aria-live="polite"
    >
      {isLoading ? (
        <>
          <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
          Generating...
        </>
      ) : (
        'Generate Recipe'
      )}
    </button>
  </div>
);

const RecipeDisplay = ({ recipe, error }) => {
    if (error) {
        return (
            <div className="mt-6 p-4 text-sm text-red-800 rounded-lg bg-red-50 dark:bg-gray-800 dark:text-red-400" role="alert">
                <span className="font-medium">Error!</span> {error}
            </div>
        );
    }

    if (!recipe) {
        return null;
    }
    
    const formatRecipe = (text) => {
        return text
            .replace(/## (.*)/g, '<h2 class="text-2xl font-bold mt-6 mb-3 text-gray-800 dark:text-white">$1</h2>')
            .replace(/### (.*)/g, '<h3 class="text-xl font-semibold mt-4 mb-2 text-gray-700 dark:text-gray-200">$1</h3>')
            .replace(/\* (.*)/g, '<li class="ml-5 list-disc text-gray-600 dark:text-gray-300">$1</li>')
            .replace(/\n/g, '<br />');
    };

  return (
    <div className="mt-8 prose dark:prose-invert max-w-none bg-gray-50 dark:bg-gray-900/50 p-6 rounded-lg shadow-inner animate-fade-in">
        <div dangerouslySetInnerHTML={{ __html: formatRecipe(recipe) }} />
    </div>
  );
};

// --- Main App Component ---

const App = () => {
  const [ingredients, setIngredients] = useState('');
  const [recipe, setRecipe] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const handleGenerateRecipe = useCallback(async () => {
    if (!ingredients.trim()) {
      setError('Please enter some ingredients.');
      return;
    }
    setIsLoading(true);
    setError('');
    setRecipe('');

    try {
      if (!process.env.API_KEY) {
        throw new Error("API_KEY environment variable is not configured.");
      }
      const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
      
      const prompt = `You are a creative chef. Generate a delicious recipe using the following ingredients: ${ingredients}.
      
      Please provide:
      1. A catchy recipe title.
      2. A list of the ingredients needed (you can use a subset of the provided ingredients).
      3. Step-by-step instructions.
      
      Format the response using markdown with a title (## Title), an ingredients section (### Ingredients), and an instructions section (### Instructions). Use asterisks for list items.`;
      
      const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: prompt,
      });
      
      setRecipe(response.text);

    } catch (err) {
      console.error(err);
      const errorMessage = err.message || 'An unknown error occurred.';
      setError(`Failed to generate recipe. ${errorMessage}`);
    } finally {
      setIsLoading(false);
    }
  }, [ingredients]);

  return (
    <div className="min-h-screen bg-gray-100 dark:bg-gray-800 text-gray-900 dark:text-gray-100 p-4 sm:p-6 lg:p-8 font-sans">
      <style>{`
        .animate-fade-in {
            animation: fadeIn 0.5s ease-in-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
      `}</style>
      <div className="max-w-2xl mx-auto bg-white dark:bg-gray-900 shadow-2xl rounded-2xl p-6 md:p-8">
        <Header />
        <main>
          <IngredientInput 
            ingredients={ingredients}
            setIngredients={setIngredients}
            onSubmit={handleGenerateRecipe}
            isLoading={isLoading}
          />
          <RecipeDisplay recipe={recipe} error={error} />
        </main>
      </div>
    </div>
  );
};

export default App;
