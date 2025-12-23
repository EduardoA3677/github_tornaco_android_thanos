.class public final Llyiahf/vczjk/uc2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/j86;
.implements Llyiahf/vczjk/nc2;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/nl1;

.field public final OooOOO0:Llyiahf/vczjk/j86;

.field public final OooOOOO:Llyiahf/vczjk/o0oo0000;

.field public OooOOOo:Llyiahf/vczjk/nc2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/j86;Llyiahf/vczjk/nl1;Llyiahf/vczjk/o0oo0000;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/uc2;->OooOOO0:Llyiahf/vczjk/j86;

    iput-object p2, p0, Llyiahf/vczjk/uc2;->OooOOO:Llyiahf/vczjk/nl1;

    iput-object p3, p0, Llyiahf/vczjk/uc2;->OooOOOO:Llyiahf/vczjk/o0oo0000;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/uc2;->OooOOOo:Llyiahf/vczjk/nc2;

    sget-object v1, Llyiahf/vczjk/tc2;->OooOOO0:Llyiahf/vczjk/tc2;

    if-eq v0, v1, :cond_0

    iput-object v1, p0, Llyiahf/vczjk/uc2;->OooOOOo:Llyiahf/vczjk/nc2;

    :try_start_0
    iget-object v1, p0, Llyiahf/vczjk/uc2;->OooOOOO:Llyiahf/vczjk/o0oo0000;

    invoke-interface {v1}, Llyiahf/vczjk/o0oo0000;->run()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v1

    invoke-static {v1}, Llyiahf/vczjk/vc6;->Oooo(Ljava/lang/Throwable;)V

    invoke-static {v1}, Llyiahf/vczjk/qu6;->OooOOOo(Ljava/lang/Throwable;)V

    :goto_0
    invoke-interface {v0}, Llyiahf/vczjk/nc2;->OooO00o()V

    :cond_0
    return-void
.end method

.method public final OooO0O0(Llyiahf/vczjk/nc2;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/uc2;->OooOOO0:Llyiahf/vczjk/j86;

    :try_start_0
    iget-object v1, p0, Llyiahf/vczjk/uc2;->OooOOO:Llyiahf/vczjk/nl1;

    invoke-interface {v1, p1}, Llyiahf/vczjk/nl1;->accept(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    iget-object v1, p0, Llyiahf/vczjk/uc2;->OooOOOo:Llyiahf/vczjk/nc2;

    invoke-static {v1, p1}, Llyiahf/vczjk/tc2;->OooO0o0(Llyiahf/vczjk/nc2;Llyiahf/vczjk/nc2;)Z

    move-result v1

    if-eqz v1, :cond_0

    iput-object p1, p0, Llyiahf/vczjk/uc2;->OooOOOo:Llyiahf/vczjk/nc2;

    invoke-interface {v0, p0}, Llyiahf/vczjk/j86;->OooO0O0(Llyiahf/vczjk/nc2;)V

    return-void

    :catchall_0
    move-exception v1

    invoke-static {v1}, Llyiahf/vczjk/vc6;->Oooo(Ljava/lang/Throwable;)V

    invoke-interface {p1}, Llyiahf/vczjk/nc2;->OooO00o()V

    sget-object p1, Llyiahf/vczjk/tc2;->OooOOO0:Llyiahf/vczjk/tc2;

    iput-object p1, p0, Llyiahf/vczjk/uc2;->OooOOOo:Llyiahf/vczjk/nc2;

    sget-object p1, Llyiahf/vczjk/xm2;->OooOOO0:Llyiahf/vczjk/xm2;

    invoke-interface {v0, p1}, Llyiahf/vczjk/j86;->OooO0O0(Llyiahf/vczjk/nc2;)V

    invoke-interface {v0, v1}, Llyiahf/vczjk/j86;->OooO0OO(Ljava/lang/Throwable;)V

    :cond_0
    return-void
.end method

.method public final OooO0OO(Ljava/lang/Throwable;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/uc2;->OooOOOo:Llyiahf/vczjk/nc2;

    sget-object v1, Llyiahf/vczjk/tc2;->OooOOO0:Llyiahf/vczjk/tc2;

    if-eq v0, v1, :cond_0

    iput-object v1, p0, Llyiahf/vczjk/uc2;->OooOOOo:Llyiahf/vczjk/nc2;

    iget-object v0, p0, Llyiahf/vczjk/uc2;->OooOOO0:Llyiahf/vczjk/j86;

    invoke-interface {v0, p1}, Llyiahf/vczjk/j86;->OooO0OO(Ljava/lang/Throwable;)V

    return-void

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/qu6;->OooOOOo(Ljava/lang/Throwable;)V

    return-void
.end method

.method public final OooO0Oo()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/uc2;->OooOOOo:Llyiahf/vczjk/nc2;

    sget-object v1, Llyiahf/vczjk/tc2;->OooOOO0:Llyiahf/vczjk/tc2;

    if-eq v0, v1, :cond_0

    iput-object v1, p0, Llyiahf/vczjk/uc2;->OooOOOo:Llyiahf/vczjk/nc2;

    iget-object v0, p0, Llyiahf/vczjk/uc2;->OooOOO0:Llyiahf/vczjk/j86;

    invoke-interface {v0}, Llyiahf/vczjk/j86;->OooO0Oo()V

    :cond_0
    return-void
.end method

.method public final OooOO0O(Ljava/lang/Object;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/uc2;->OooOOO0:Llyiahf/vczjk/j86;

    invoke-interface {v0, p1}, Llyiahf/vczjk/j86;->OooOO0O(Ljava/lang/Object;)V

    return-void
.end method
