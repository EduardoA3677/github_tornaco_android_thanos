.class public final Llyiahf/vczjk/v00;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO:Ljava/util/concurrent/atomic/AtomicReference;

.field public final OooO00o:Llyiahf/vczjk/oO0OOo0o;

.field public final OooO0O0:Llyiahf/vczjk/or1;

.field public final OooO0OO:Llyiahf/vczjk/s29;

.field public OooO0Oo:I

.field public final OooO0o:Llyiahf/vczjk/r00;

.field public final OooO0o0:Ljava/util/concurrent/atomic/AtomicReference;

.field public final OooO0oO:Ljava/util/concurrent/atomic/AtomicInteger;

.field public final OooO0oo:Llyiahf/vczjk/f43;

.field public final OooOO0:Ljava/util/concurrent/CopyOnWriteArrayList;

.field public final OooOO0O:Llyiahf/vczjk/m00;

.field public final OooOO0o:Llyiahf/vczjk/sc9;

.field public final OooOOO0:Llyiahf/vczjk/js2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oO0OOo0o;Llyiahf/vczjk/or1;Llyiahf/vczjk/or1;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/v00;->OooO00o:Llyiahf/vczjk/oO0OOo0o;

    iput-object p3, p0, Llyiahf/vczjk/v00;->OooO0O0:Llyiahf/vczjk/or1;

    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {p1}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/v00;->OooO0OO:Llyiahf/vczjk/s29;

    new-instance p1, Ljava/util/concurrent/atomic/AtomicReference;

    const/4 p3, 0x0

    invoke-direct {p1, p3}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    iput-object p1, p0, Llyiahf/vczjk/v00;->OooO0o0:Ljava/util/concurrent/atomic/AtomicReference;

    new-instance p1, Llyiahf/vczjk/r00;

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/r00;-><init>(Llyiahf/vczjk/v00;Llyiahf/vczjk/or1;)V

    iput-object p1, p0, Llyiahf/vczjk/v00;->OooO0o:Llyiahf/vczjk/r00;

    new-instance p2, Ljava/util/concurrent/atomic/AtomicInteger;

    const/4 v0, 0x0

    invoke-direct {p2, v0}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    iput-object p2, p0, Llyiahf/vczjk/v00;->OooO0oO:Ljava/util/concurrent/atomic/AtomicInteger;

    new-instance p2, Llyiahf/vczjk/wh;

    iget-object v0, p1, Llyiahf/vczjk/kn6;->OooOO0O:Llyiahf/vczjk/gh7;

    const/4 v1, 0x4

    invoke-direct {p2, v0, v1}, Llyiahf/vczjk/wh;-><init>(Llyiahf/vczjk/f43;I)V

    const/4 v0, -0x1

    invoke-static {p2, v0}, Llyiahf/vczjk/rs;->OooOO0(Llyiahf/vczjk/f43;I)Llyiahf/vczjk/f43;

    move-result-object p2

    new-instance v0, Llyiahf/vczjk/u00;

    invoke-direct {v0, p2, p3, p0}, Llyiahf/vczjk/u00;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/yo1;Llyiahf/vczjk/v00;)V

    new-instance p2, Llyiahf/vczjk/s48;

    invoke-direct {p2, v0}, Llyiahf/vczjk/s48;-><init>(Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v0, Llyiahf/vczjk/y95;->OooO00o:Llyiahf/vczjk/xl3;

    invoke-static {p2, v0}, Llyiahf/vczjk/rs;->OooOoo(Llyiahf/vczjk/f43;Llyiahf/vczjk/qr1;)Llyiahf/vczjk/f43;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/v00;->OooO0oo:Llyiahf/vczjk/f43;

    iget-object p1, p1, Llyiahf/vczjk/kn6;->OooOO0o:Llyiahf/vczjk/jl8;

    new-instance p2, Llyiahf/vczjk/eh7;

    invoke-direct {p2, p1}, Llyiahf/vczjk/eh7;-><init>(Llyiahf/vczjk/os5;)V

    new-instance p1, Ljava/util/concurrent/atomic/AtomicReference;

    invoke-direct {p1, p3}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    iput-object p1, p0, Llyiahf/vczjk/v00;->OooO:Ljava/util/concurrent/atomic/AtomicReference;

    new-instance p1, Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-direct {p1}, Ljava/util/concurrent/CopyOnWriteArrayList;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/v00;->OooOO0:Ljava/util/concurrent/CopyOnWriteArrayList;

    new-instance p1, Llyiahf/vczjk/m00;

    invoke-direct {p1, p0}, Llyiahf/vczjk/m00;-><init>(Llyiahf/vczjk/v00;)V

    iput-object p1, p0, Llyiahf/vczjk/v00;->OooOO0O:Llyiahf/vczjk/m00;

    sget-object p1, Llyiahf/vczjk/u;->OooOoo:Llyiahf/vczjk/u;

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/v00;->OooOO0o:Llyiahf/vczjk/sc9;

    new-instance p1, Llyiahf/vczjk/js2;

    invoke-direct {p1, p0}, Llyiahf/vczjk/js2;-><init>(Llyiahf/vczjk/v00;)V

    iput-object p1, p0, Llyiahf/vczjk/v00;->OooOOO0:Llyiahf/vczjk/js2;

    return-void
.end method
