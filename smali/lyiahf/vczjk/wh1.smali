.class public final Llyiahf/vczjk/wh1;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO:I

.field public final OooO00o:Ljava/util/concurrent/ExecutorService;

.field public final OooO0O0:Llyiahf/vczjk/q32;

.field public final OooO0OO:Ljava/util/concurrent/ExecutorService;

.field public final OooO0Oo:Llyiahf/vczjk/vp3;

.field public final OooO0o:Llyiahf/vczjk/xj0;

.field public final OooO0o0:Llyiahf/vczjk/ws7;

.field public final OooO0oO:Llyiahf/vczjk/sw7;

.field public final OooO0oo:I

.field public final OooOO0:I

.field public final OooOO0O:I

.field public final OooOO0o:Z

.field public final OooOOO0:Llyiahf/vczjk/e86;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wp3;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 p1, 0x0

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOOO0(Z)Ljava/util/concurrent/ExecutorService;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/wh1;->OooO00o:Ljava/util/concurrent/ExecutorService;

    sget-object p1, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    iput-object p1, p0, Llyiahf/vczjk/wh1;->OooO0O0:Llyiahf/vczjk/q32;

    const/4 p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOOO0(Z)Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/wh1;->OooO0OO:Ljava/util/concurrent/ExecutorService;

    new-instance v0, Llyiahf/vczjk/vp3;

    const/16 v1, 0x19

    invoke-direct {v0, v1}, Llyiahf/vczjk/vp3;-><init>(I)V

    iput-object v0, p0, Llyiahf/vczjk/wh1;->OooO0Oo:Llyiahf/vczjk/vp3;

    sget-object v0, Llyiahf/vczjk/ws7;->OooOOOO:Llyiahf/vczjk/ws7;

    iput-object v0, p0, Llyiahf/vczjk/wh1;->OooO0o0:Llyiahf/vczjk/ws7;

    sget-object v0, Llyiahf/vczjk/xj0;->OooOo00:Llyiahf/vczjk/xj0;

    iput-object v0, p0, Llyiahf/vczjk/wh1;->OooO0o:Llyiahf/vczjk/xj0;

    new-instance v0, Llyiahf/vczjk/sw7;

    const/16 v1, 0xd

    invoke-direct {v0, v1}, Llyiahf/vczjk/sw7;-><init>(I)V

    iput-object v0, p0, Llyiahf/vczjk/wh1;->OooO0oO:Llyiahf/vczjk/sw7;

    const/4 v0, 0x4

    iput v0, p0, Llyiahf/vczjk/wh1;->OooO0oo:I

    const v0, 0x7fffffff

    iput v0, p0, Llyiahf/vczjk/wh1;->OooO:I

    const/16 v0, 0x14

    iput v0, p0, Llyiahf/vczjk/wh1;->OooOO0O:I

    const/16 v0, 0x8

    iput v0, p0, Llyiahf/vczjk/wh1;->OooOO0:I

    iput-boolean p1, p0, Llyiahf/vczjk/wh1;->OooOO0o:Z

    new-instance p1, Llyiahf/vczjk/e86;

    const/16 v0, 0xd

    invoke-direct {p1, v0}, Llyiahf/vczjk/e86;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/wh1;->OooOOO0:Llyiahf/vczjk/e86;

    return-void
.end method
