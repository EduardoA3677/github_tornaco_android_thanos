.class public final Llyiahf/vczjk/fh1;
.super Llyiahf/vczjk/h88;
.source "SourceFile"


# instance fields
.field public final OooOOO:Llyiahf/vczjk/cg1;

.field public final OooOOO0:Llyiahf/vczjk/cg1;

.field public final OooOOOO:Llyiahf/vczjk/cg1;

.field public final OooOOOo:Llyiahf/vczjk/hh1;

.field public volatile OooOOo0:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hh1;)V
    .locals 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/fh1;->OooOOOo:Llyiahf/vczjk/hh1;

    new-instance p1, Llyiahf/vczjk/cg1;

    const/4 v0, 0x1

    invoke-direct {p1, v0}, Llyiahf/vczjk/cg1;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/fh1;->OooOOO0:Llyiahf/vczjk/cg1;

    new-instance v0, Llyiahf/vczjk/cg1;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/cg1;-><init>(I)V

    iput-object v0, p0, Llyiahf/vczjk/fh1;->OooOOO:Llyiahf/vczjk/cg1;

    new-instance v1, Llyiahf/vczjk/cg1;

    const/4 v2, 0x1

    invoke-direct {v1, v2}, Llyiahf/vczjk/cg1;-><init>(I)V

    iput-object v1, p0, Llyiahf/vczjk/fh1;->OooOOOO:Llyiahf/vczjk/cg1;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/cg1;->OooO0O0(Llyiahf/vczjk/nc2;)Z

    invoke-virtual {v1, v0}, Llyiahf/vczjk/cg1;->OooO0O0(Llyiahf/vczjk/nc2;)Z

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/fh1;->OooOOo0:Z

    if-nez v0, :cond_0

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/fh1;->OooOOo0:Z

    iget-object v0, p0, Llyiahf/vczjk/fh1;->OooOOOO:Llyiahf/vczjk/cg1;

    invoke-virtual {v0}, Llyiahf/vczjk/cg1;->OooO00o()V

    :cond_0
    return-void
.end method

.method public final OooO0OO(Ljava/lang/Runnable;)Llyiahf/vczjk/nc2;
    .locals 6

    iget-boolean v0, p0, Llyiahf/vczjk/fh1;->OooOOo0:Z

    if-eqz v0, :cond_0

    sget-object p1, Llyiahf/vczjk/xm2;->OooOOO0:Llyiahf/vczjk/xm2;

    return-object p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/fh1;->OooOOOo:Llyiahf/vczjk/hh1;

    sget-object v4, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    iget-object v5, p0, Llyiahf/vczjk/fh1;->OooOOO0:Llyiahf/vczjk/cg1;

    const-wide/16 v2, 0x0

    move-object v1, p1

    invoke-virtual/range {v0 .. v5}, Llyiahf/vczjk/c16;->OooO0o0(Ljava/lang/Runnable;JLjava/util/concurrent/TimeUnit;Llyiahf/vczjk/cg1;)Llyiahf/vczjk/f88;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0Oo(Ljava/lang/Runnable;JLjava/util/concurrent/TimeUnit;)Llyiahf/vczjk/nc2;
    .locals 6

    iget-boolean v0, p0, Llyiahf/vczjk/fh1;->OooOOo0:Z

    if-eqz v0, :cond_0

    sget-object p1, Llyiahf/vczjk/xm2;->OooOOO0:Llyiahf/vczjk/xm2;

    return-object p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/fh1;->OooOOOo:Llyiahf/vczjk/hh1;

    iget-object v5, p0, Llyiahf/vczjk/fh1;->OooOOO:Llyiahf/vczjk/cg1;

    move-object v1, p1

    move-wide v2, p2

    move-object v4, p4

    invoke-virtual/range {v0 .. v5}, Llyiahf/vczjk/c16;->OooO0o0(Ljava/lang/Runnable;JLjava/util/concurrent/TimeUnit;Llyiahf/vczjk/cg1;)Llyiahf/vczjk/f88;

    move-result-object p1

    return-object p1
.end method
