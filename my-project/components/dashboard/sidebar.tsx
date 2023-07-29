import React from 'react'
import { Dashboard } from '../../components/svg/admin/dashboard'
import { User } from '../../components/svg/admin/user'
import { PostIcon } from '../../components/svg/admin/post'
import { Tag } from '../../components/svg/admin/tag'
import { CommentIcon } from '../../components/svg/admin/comment'
import { Project } from '../../components/svg/admin/project'
import { Setting } from '../../components/svg/admin/setting'
import { Navigation } from '../reuseable/navigation'
export const Sidebar = () => {
    return (
        <aside className='fixed inset-0 overflow-auto p-4 w-60 bg-darkBlue'>
            <nav className="h-full">
                <ul className="flex  flex-col flex-grow-1 space-y-8 text-white">
                    <li className="uppercase tracking-widest text-base mt-3">
                        <h3>Action</h3>
                    </li>
                    <li className='flex space-x-4 hover:text-accentCyan'>
                        <Dashboard />
                        <Navigation href="/admin"><span>Dashboard</span></Navigation>

                    </li>
                    <li className='flex space-x-4 hover:text-accentCyan'>
                        <User />
                        <Navigation href="/admin/users"><span>Users</span></Navigation>
                    </li>
                    <li className='flex space-x-4 hover:text-accentCyan'>
                        <PostIcon />

                        <Navigation href="/admin/users"><span>Posts</span></Navigation>

                    </li>
                    <li className='flex space-x-4 hover:text-accentCyan'>
                        <Tag />
                        <Navigation href="/admin/tags"><span>Posts</span></Navigation>
                    </li>
                    <li className='flex space-x-4 hover:text-accentCyan'>
                        <CommentIcon />
                        <Navigation href="/admin/comments"><span>Posts</span></Navigation>
                    </li>
                    <li className='flex space-x-4 hover:text-accentCyan'>
                        <Project />
                        <Navigation href="/admin/projects"><span>Posts</span></Navigation>
                    </li>
                    <li className="uppercase tracking-widest text-base mt-3">
                        <h3>Settings</h3>
                    </li>
                    <li className='flex space-x-4 hover:text-accentCyan'>
                        <Setting />
                        <Navigation href="/admin/settings"><span>Posts</span></Navigation>
                    </li>

                </ul>

            </nav>
        </aside>
    )
}
