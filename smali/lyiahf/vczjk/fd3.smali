.class public abstract Llyiahf/vczjk/fd3;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/ed3;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    sget-object v0, Llyiahf/vczjk/ed3;->OooO00o:Llyiahf/vczjk/ed3;

    sput-object v0, Llyiahf/vczjk/fd3;->OooO00o:Llyiahf/vczjk/ed3;

    return-void
.end method

.method public static OooO00o(Landroidx/fragment/app/Oooo0;)Llyiahf/vczjk/ed3;
    .locals 2

    :goto_0
    if-eqz p0, :cond_1

    invoke-virtual {p0}, Landroidx/fragment/app/Oooo0;->isAdded()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Landroidx/fragment/app/Oooo0;->getParentFragmentManager()Landroidx/fragment/app/oo000o;

    move-result-object v0

    const-string v1, "declaringFragment.parentFragmentManager"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    :cond_0
    invoke-virtual {p0}, Landroidx/fragment/app/Oooo0;->getParentFragment()Landroidx/fragment/app/Oooo0;

    move-result-object p0

    goto :goto_0

    :cond_1
    sget-object p0, Llyiahf/vczjk/fd3;->OooO00o:Llyiahf/vczjk/ed3;

    return-object p0
.end method

.method public static OooO0O0(Llyiahf/vczjk/pja;)V
    .locals 2

    const/4 v0, 0x3

    invoke-static {v0}, Landroidx/fragment/app/oo000o;->Oooo0OO(I)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/pja;->OooO00o()Landroidx/fragment/app/Oooo0;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    const-string v1, "StrictMode violation in "

    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    const-string v1, "FragmentManager"

    invoke-static {v1, v0, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :cond_0
    return-void
.end method

.method public static final OooO0OO(Landroidx/fragment/app/Oooo0;Ljava/lang/String;)V
    .locals 1

    const-string v0, "fragment"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "previousFragmentId"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/cd3;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/cd3;-><init>(Landroidx/fragment/app/Oooo0;Ljava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/fd3;->OooO0O0(Llyiahf/vczjk/pja;)V

    invoke-static {p0}, Llyiahf/vczjk/fd3;->OooO00o(Landroidx/fragment/app/Oooo0;)Llyiahf/vczjk/ed3;

    move-result-object p0

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    return-void
.end method
