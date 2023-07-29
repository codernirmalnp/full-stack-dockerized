import React from 'react'
import { useState } from 'react'
import Dark from '../svg/dark'
import Light from '../svg/light'
const Header = () => {
    const [theme, setTheme] = useState<string>("light")
    const handleChangeTheme = () => {
        const colorTheme = theme;
        const newTheme = colorTheme === "dark" ? "light" : "dark"
        const root = window.document.documentElement;
        root.classList.remove(colorTheme)
        root.classList.add(newTheme)
        setTheme(newTheme)
        localStorage.setItem("colorTheme", newTheme)
    }
    return (
        <header className="container mx-auto mt-0 px-6 text-center h-40 md:h-20">

            <div
                className="bg-logo-light-mode dark:bg-logo-dark-mode bg-no-repeat h-20 w-48 mx-auto md:mx-0 md:absolute top-10 left-10"
            ></div>

            <div
                className="flex items-center justify-center space-x-4 md:space-x-10 md:absolute top-12 right-10"
            >
                <a href="#features" className="hover:text-accentCyan">Projects</a>
                <a href="#testimonials" className="hover:text-accentCyan">Blog</a>
               


                <button
                    id="theme-toggle"
                    className="text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 focus:outline-none focus:ring-4 focus:ring-gray-200 dark:focus:ring-gray-700 rounded-lg text-sm p-2 5"
                    onClick={handleChangeTheme}
                >
                    {theme === 'dark' ? <Light /> : <Dark />}



                </button>
            </div>
        </header>
    )
}

export default Header;