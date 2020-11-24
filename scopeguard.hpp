#ifndef NKLIB_SCOPEGUARD_HPP_
#define NKLIB_SCOPEGUARD_HPP_

// The code here was written after watching
// Andrei Alexandrescu's presentation at
// http://channel9.msdn.com/Shows/Going+Deep/C-and-Beyond-2012-Andrei-Alexandrescu-Systematic-Error-Handling-in-C

// Usage: SCOPE_EXIT { LAMBDA_CONTENTS };
// 
// Or, if cancelling the action in some cases is necessary:
// auto sg = scopeGuard([]{ LAMBDA_CONTENTS });
// ... do work ...
// sg.dismiss();

namespace nk {
    template <class Fn>
    class ScopeGuard {
        Fn f_;
        bool active_;
    public:
        ScopeGuard(Fn f) : f_(std::move(f)), active_(true) {}
        ~ScopeGuard() { if (active_) f_(); }

        ScopeGuard() = delete;
        ScopeGuard(const ScopeGuard&) = delete;
        ScopeGuard& operator=(const ScopeGuard&) = delete;

        void dismiss() { active_ = false; }

        // Necessary for the non-member wrapper function below.
        ScopeGuard(ScopeGuard&& rhs) : f_(std::move(rhs.f_)),
                                       active_(rhs.active_) {
            rhs.dismiss(); // Don't dismiss twice.
        }
    };

    // Class templates don't allow for type inference, so wrap with
    // a function to provide type inference.  Move semantics avoids a cost.
    template <class Fn>
    ScopeGuard<Fn> scopeGuard(Fn f) {
        return ScopeGuard<Fn>(std::move(f));
    }

    // Tricky bits that are needed for SCOPE_EXIT below.
    namespace detail {
        enum class ScopeGuardOnExit {};
        template <typename Fn> ScopeGuard<Fn>
        operator+(ScopeGuardOnExit, Fn&& fn) {
            return ScopeGuard<Fn>(std::forward<Fn>(fn));
        }
    }
}

// GCC, MSVC, and ICC all support __COUNTER__.
#define SCOPE_MACRO_CONCAT_DO(a,b) a##b
#define SCOPE_MACRO_CONCAT(a,b) SCOPE_MACRO_CONCAT_DO(a,b)
#ifdef __COUNTER__
#define SCOPE_ANONYMOUS_VARIABLE(str) SCOPE_MACRO_CONCAT(str, __COUNTER__)
#else
#define SCOPE_ANONYMOUS_VARIABLE(str) SCOPE_MACRO_CONCAT(str, __LINE__)
#endif

#define SCOPE_EXIT \
    auto SCOPE_ANONYMOUS_VARIABLE(scope_exit_state_)   \
    = nk::detail::ScopeGuardOnExit() + [&]()

#endif

