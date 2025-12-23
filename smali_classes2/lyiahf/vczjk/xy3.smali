.class public final synthetic Llyiahf/vczjk/xy3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/xy3;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/xy3;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 12

    iget v0, p0, Llyiahf/vczjk/xy3;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/xy3;->OooOOO:Ljava/lang/Object;

    check-cast v0, Ljava/lang/Runnable;

    invoke-static {v0}, Lgithub/tornaco/thanox/android/server/patch/framework/ThanoxHookImpl;->OooO00o(Ljava/lang/Runnable;)V

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/xy3;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/wl9;

    const/4 v1, 0x0

    iput-object v1, v0, Llyiahf/vczjk/wl9;->OooOOO:Llyiahf/vczjk/xy3;

    iget-object v2, v0, Llyiahf/vczjk/wl9;->OooO00o:Landroid/view/View;

    invoke-virtual {v2}, Landroid/view/View;->isFocused()Z

    move-result v3

    const/4 v4, 0x1

    iget-object v5, v0, Llyiahf/vczjk/wl9;->OooOOO0:Llyiahf/vczjk/ws5;

    if-nez v3, :cond_0

    invoke-virtual {v2}, Landroid/view/View;->getRootView()Landroid/view/View;

    move-result-object v2

    invoke-virtual {v2}, Landroid/view/View;->findFocus()Landroid/view/View;

    move-result-object v2

    if-eqz v2, :cond_0

    invoke-virtual {v2}, Landroid/view/View;->onCheckIsTextEditor()Z

    move-result v2

    if-ne v2, v4, :cond_0

    invoke-virtual {v5}, Llyiahf/vczjk/ws5;->OooO0oO()V

    goto/16 :goto_5

    :cond_0
    iget-object v2, v5, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v3, v5, Llyiahf/vczjk/ws5;->OooOOOO:I

    const/4 v6, 0x0

    move-object v7, v1

    move v8, v6

    :goto_0
    if-ge v8, v3, :cond_6

    aget-object v9, v2, v8

    check-cast v9, Llyiahf/vczjk/ul9;

    invoke-virtual {v9}, Ljava/lang/Enum;->ordinal()I

    move-result v10

    if-eqz v10, :cond_4

    if-eq v10, v4, :cond_3

    const/4 v11, 0x2

    if-eq v10, v11, :cond_1

    const/4 v11, 0x3

    if-eq v10, v11, :cond_1

    goto :goto_3

    :cond_1
    sget-object v10, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v1, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-nez v10, :cond_5

    sget-object v7, Llyiahf/vczjk/ul9;->OooOOOO:Llyiahf/vczjk/ul9;

    if-ne v9, v7, :cond_2

    move v7, v4

    goto :goto_1

    :cond_2
    move v7, v6

    :goto_1
    invoke-static {v7}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v7

    goto :goto_3

    :cond_3
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    :goto_2
    move-object v7, v1

    goto :goto_3

    :cond_4
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    goto :goto_2

    :cond_5
    :goto_3
    add-int/lit8 v8, v8, 0x1

    goto :goto_0

    :cond_6
    invoke-virtual {v5}, Llyiahf/vczjk/ws5;->OooO0oO()V

    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    iget-object v0, v0, Llyiahf/vczjk/wl9;->OooO0O0:Llyiahf/vczjk/o04;

    if-eqz v2, :cond_7

    iget-object v2, v0, Llyiahf/vczjk/o04;->OooO0O0:Ljava/lang/Object;

    invoke-interface {v2}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroid/view/inputmethod/InputMethodManager;

    iget-object v3, v0, Llyiahf/vczjk/o04;->OooO00o:Landroid/view/View;

    invoke-virtual {v2, v3}, Landroid/view/inputmethod/InputMethodManager;->restartInput(Landroid/view/View;)V

    :cond_7
    if-eqz v7, :cond_9

    invoke-virtual {v7}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v2

    if-eqz v2, :cond_8

    iget-object v2, v0, Llyiahf/vczjk/o04;->OooO0OO:Llyiahf/vczjk/wg7;

    iget-object v2, v2, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/gv7;

    invoke-virtual {v2}, Llyiahf/vczjk/gv7;->OooO0OO()V

    goto :goto_4

    :cond_8
    iget-object v2, v0, Llyiahf/vczjk/o04;->OooO0OO:Llyiahf/vczjk/wg7;

    iget-object v2, v2, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/gv7;

    invoke-virtual {v2}, Llyiahf/vczjk/gv7;->OooO0O0()V

    :cond_9
    :goto_4
    sget-object v2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_a

    iget-object v1, v0, Llyiahf/vczjk/o04;->OooO0O0:Ljava/lang/Object;

    invoke-interface {v1}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroid/view/inputmethod/InputMethodManager;

    iget-object v0, v0, Llyiahf/vczjk/o04;->OooO00o:Landroid/view/View;

    invoke-virtual {v1, v0}, Landroid/view/inputmethod/InputMethodManager;->restartInput(Landroid/view/View;)V

    :cond_a
    :goto_5
    return-void

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/xy3;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lcom/google/android/material/textfield/TextInputLayout;

    iget-object v0, v0, Lcom/google/android/material/textfield/TextInputLayout;->OooOOo0:Landroid/widget/EditText;

    invoke-virtual {v0}, Landroid/view/View;->requestLayout()V

    return-void

    :pswitch_2
    iget-object v0, p0, Llyiahf/vczjk/xy3;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ed9;

    iget-object v0, v0, Llyiahf/vczjk/ed9;->OooO00o:Llyiahf/vczjk/cd9;

    invoke-virtual {v0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    move-result-object v1

    instance-of v2, v1, Landroid/view/ViewGroup;

    if-eqz v2, :cond_b

    check-cast v1, Landroid/view/ViewGroup;

    invoke-virtual {v1, v0}, Landroid/view/ViewGroup;->removeView(Landroid/view/View;)V

    :cond_b
    return-void

    :pswitch_3
    iget-object v0, p0, Llyiahf/vczjk/xy3;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/jf0;

    const/4 v1, 0x0

    iput-boolean v1, v0, Llyiahf/vczjk/jf0;->OooO0OO:Z

    iget-object v1, v0, Llyiahf/vczjk/jf0;->OooO0o0:Ljava/lang/Object;

    check-cast v1, Lcom/google/android/material/sidesheet/SideSheetBehavior;

    iget-object v2, v1, Lcom/google/android/material/sidesheet/SideSheetBehavior;->OooOo0:Llyiahf/vczjk/iga;

    if-eqz v2, :cond_c

    invoke-virtual {v2}, Llyiahf/vczjk/iga;->OooO0oo()Z

    move-result v2

    if-eqz v2, :cond_c

    iget v1, v0, Llyiahf/vczjk/jf0;->OooO0O0:I

    invoke-virtual {v0, v1}, Llyiahf/vczjk/jf0;->OooO0O0(I)V

    goto :goto_6

    :cond_c
    iget v2, v1, Lcom/google/android/material/sidesheet/SideSheetBehavior;->OooOo00:I

    const/4 v3, 0x2

    if-ne v2, v3, :cond_d

    iget v0, v0, Llyiahf/vczjk/jf0;->OooO0O0:I

    invoke-virtual {v1, v0}, Lcom/google/android/material/sidesheet/SideSheetBehavior;->OooOo(I)V

    :cond_d
    :goto_6
    return-void

    :pswitch_4
    iget-object v0, p0, Llyiahf/vczjk/xy3;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/om8;

    iget-object v1, v0, Llyiahf/vczjk/om8;->OooO0o0:Ljava/util/HashSet;

    invoke-virtual {v1}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_7
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_e

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/content/ServiceConnection;

    iget-object v4, v0, Llyiahf/vczjk/om8;->OooO0o:Landroid/content/ComponentName;

    invoke-interface {v3, v4}, Landroid/content/ServiceConnection;->onServiceDisconnected(Landroid/content/ComponentName;)V

    goto :goto_7

    :cond_e
    invoke-virtual {v1}, Ljava/util/HashSet;->clear()V

    invoke-static {v0}, Llyiahf/vczjk/pm8;->OooO00o(Llyiahf/vczjk/om8;)V

    return-void

    :pswitch_5
    iget-object v0, p0, Llyiahf/vczjk/xy3;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/tm8;

    iget-object v0, v0, Llyiahf/vczjk/tm8;->OooO00o:Llyiahf/vczjk/vm8;

    invoke-virtual {v0}, Llyiahf/vczjk/vm8;->OooO()V

    return-void

    :pswitch_6
    iget-object v0, p0, Llyiahf/vczjk/xy3;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/sm8;

    invoke-virtual {v0}, Llyiahf/vczjk/sm8;->OooO00o()V

    return-void

    :pswitch_7
    iget-object v0, p0, Llyiahf/vczjk/xy3;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lcom/topjohnwu/superuser/fallback/Shell$GetShellCallback;

    invoke-static {v0}, Lcom/topjohnwu/superuser/fallback/Shell;->OooO0Oo(Lcom/topjohnwu/superuser/fallback/Shell$GetShellCallback;)V

    return-void

    :pswitch_8
    iget-object v0, p0, Llyiahf/vczjk/xy3;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lgithub/tornaco/android/thanos/core/profile/RuleAddCallback;

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/profile/RuleAddCallback;->onRuleAddSuccess()V

    return-void

    :pswitch_9
    iget-object v0, p0, Llyiahf/vczjk/xy3;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/xt7;

    invoke-static {v0}, Llyiahf/vczjk/xt7;->OooO00o(Llyiahf/vczjk/xt7;)V

    return-void

    :pswitch_a
    iget-object v0, p0, Llyiahf/vczjk/xy3;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lio/github/libxposed/service/RemotePreferences$Editor;

    invoke-static {v0}, Lio/github/libxposed/service/RemotePreferences$Editor;->OooO00o(Lio/github/libxposed/service/RemotePreferences$Editor;)V

    return-void

    :pswitch_b
    iget-object v0, p0, Llyiahf/vczjk/xy3;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/f57;

    iget v1, v0, Llyiahf/vczjk/f57;->OooOOO:I

    const/4 v2, 0x1

    iget-object v3, v0, Llyiahf/vczjk/f57;->OooOOo:Llyiahf/vczjk/wy4;

    if-nez v1, :cond_f

    iput-boolean v2, v0, Llyiahf/vczjk/f57;->OooOOOO:Z

    sget-object v1, Llyiahf/vczjk/iy4;->ON_PAUSE:Llyiahf/vczjk/iy4;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/wy4;->OooO0o(Llyiahf/vczjk/iy4;)V

    :cond_f
    iget v1, v0, Llyiahf/vczjk/f57;->OooOOO0:I

    if-nez v1, :cond_10

    iget-boolean v1, v0, Llyiahf/vczjk/f57;->OooOOOO:Z

    if-eqz v1, :cond_10

    sget-object v1, Llyiahf/vczjk/iy4;->ON_STOP:Llyiahf/vczjk/iy4;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/wy4;->OooO0o(Llyiahf/vczjk/iy4;)V

    iput-boolean v2, v0, Llyiahf/vczjk/f57;->OooOOOo:Z

    :cond_10
    return-void

    :pswitch_c
    iget-object v0, p0, Llyiahf/vczjk/xy3;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/k07;

    iget-object v0, v0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    const-string v1, "power"

    invoke-virtual {v0, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v0

    const-string v1, "null cannot be cast to non-null type android.os.PowerManager"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Landroid/os/PowerManager;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Landroid/os/PowerManager;->reboot(Ljava/lang/String;)V

    return-void

    :pswitch_d
    iget-object v0, p0, Llyiahf/vczjk/xy3;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/sv6;

    iget-object v0, v0, Llyiahf/vczjk/sv6;->OooO00o:Llyiahf/vczjk/uv6;

    iget-object v1, v0, Llyiahf/vczjk/uv6;->OoooO:Llyiahf/vczjk/n36;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/uv6;->OooOo(Lgithub/tornaco/android/thanos/core/util/function/Predicate;)V

    return-void

    :pswitch_e
    iget-object v0, p0, Llyiahf/vczjk/xy3;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ed5;

    iget-object v1, v0, Llyiahf/vczjk/ed5;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/od5;

    if-eqz v1, :cond_11

    iget-object v2, v0, Llyiahf/vczjk/ed5;->OooOOOo:Ljava/lang/Object;

    check-cast v2, Landroid/widget/FrameLayout;

    iget-object v0, v0, Llyiahf/vczjk/ed5;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/nd5;

    const/4 v3, 0x1

    invoke-virtual {v1, v0, v2, v3}, Llyiahf/vczjk/od5;->OooO0O0(Llyiahf/vczjk/nd5;Landroid/view/View;Z)V

    :cond_11
    return-void

    :pswitch_f
    iget-object v0, p0, Llyiahf/vczjk/xy3;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lcom/google/android/material/button/MaterialButton;

    invoke-static {v0}, Lcom/google/android/material/button/MaterialButton;->OooO00o(Lcom/google/android/material/button/MaterialButton;)V

    return-void

    :pswitch_10
    iget-object v0, p0, Llyiahf/vczjk/xy3;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/f95;

    invoke-virtual {v0}, Llyiahf/vczjk/f95;->OooO0OO()V

    return-void

    :pswitch_11
    iget-object v0, p0, Llyiahf/vczjk/xy3;->OooOOO:Ljava/lang/Object;

    check-cast v0, Ljava/io/ByteArrayInputStream;

    invoke-static {v0}, Llyiahf/vczjk/qba;->OooO0O0(Ljava/io/Closeable;)V

    return-void

    :pswitch_12
    iget-object v0, p0, Llyiahf/vczjk/xy3;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/v74;

    if-eqz v0, :cond_12

    const/4 v1, 0x0

    invoke-interface {v0, v1}, Llyiahf/vczjk/v74;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    :cond_12
    return-void

    :pswitch_13
    iget-object v0, p0, Llyiahf/vczjk/xy3;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lnow/fortuitous/app/view/LaneView;

    iget-object v1, v0, Lnow/fortuitous/app/view/LaneView;->OooOo0o:Landroid/util/ArrayMap;

    invoke-virtual {v1}, Landroid/util/ArrayMap;->values()Ljava/util/Collection;

    move-result-object v1

    const-string v2, "<get-values>(...)"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v1, Ljava/lang/Iterable;

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    const/4 v2, 0x1

    :goto_8
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_13

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/wm4;

    iget-object v3, v3, Llyiahf/vczjk/wm4;->OooO0o0:Landroid/util/ArrayMap;

    invoke-virtual {v3}, Landroid/util/ArrayMap;->isEmpty()Z

    move-result v3

    and-int/2addr v2, v3

    goto :goto_8

    :cond_13
    if-eqz v2, :cond_14

    iget-object v0, v0, Lnow/fortuitous/app/view/LaneView;->OooOOo:Llyiahf/vczjk/le3;

    if-eqz v0, :cond_14

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    :cond_14
    return-void

    :pswitch_14
    iget-object v0, p0, Llyiahf/vczjk/xy3;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lnow/fortuitous/app/infinite/OooO00o;

    invoke-virtual {v0}, Lnow/fortuitous/app/infinite/OooO00o;->OooOo0o()I

    move-result v1

    invoke-static {v1}, Lnow/fortuitous/app/infinite/OooO00o;->OooOoo0(I)Z

    move-result v1

    if-nez v1, :cond_15

    invoke-virtual {v0}, Lnow/fortuitous/app/infinite/OooO00o;->OooOo0O()V

    invoke-virtual {v0}, Lnow/fortuitous/app/infinite/OooO00o;->OooOooO()V

    :cond_15
    return-void

    :pswitch_15
    iget-object v0, p0, Llyiahf/vczjk/xy3;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/dl5;

    invoke-virtual {v0}, Llyiahf/vczjk/dl5;->OooO00o()V

    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
