.class public final Llyiahf/vczjk/k52;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/w89;


# static fields
.field public static final synthetic OooO0Oo:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;


# instance fields
.field public final OooO00o:J

.field public final OooO0O0:Llyiahf/vczjk/jj0;

.field public volatile synthetic OooO0OO:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    const-class v0, Llyiahf/vczjk/k52;

    const-string v1, "OooO0OO"

    invoke-static {v0, v1}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/k52;->OooO0Oo:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/to1;J)V
    .locals 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-wide p2, p0, Llyiahf/vczjk/k52;->OooO00o:J

    const/4 p2, 0x6

    const/4 p3, -0x2

    const/4 v0, 0x0

    invoke-static {p3, p2, v0}, Llyiahf/vczjk/tg0;->OooO0o0(IILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jj0;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/k52;->OooO0O0:Llyiahf/vczjk/jj0;

    new-instance p3, Llyiahf/vczjk/ss0;

    const/4 v1, 0x0

    invoke-direct {p3, p2, v1}, Llyiahf/vczjk/ss0;-><init>(Llyiahf/vczjk/ui7;Z)V

    new-instance p2, Llyiahf/vczjk/j52;

    invoke-direct {p2, p0}, Llyiahf/vczjk/j52;-><init>(Llyiahf/vczjk/k52;)V

    new-instance v2, Llyiahf/vczjk/g53;

    invoke-direct {v2, p2, p3, v0}, Llyiahf/vczjk/g53;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/f43;Llyiahf/vczjk/yo1;)V

    new-instance p2, Llyiahf/vczjk/y30;

    const/4 p3, 0x2

    invoke-direct {p2, v2, p3}, Llyiahf/vczjk/y30;-><init>(Ljava/lang/Object;I)V

    sget-object p3, Llyiahf/vczjk/ql8;->OooO00o:Llyiahf/vczjk/wp3;

    sget-object v0, Llyiahf/vczjk/b99;->OooOOO0:Llyiahf/vczjk/b99;

    invoke-static {p2, p1, p3, v0}, Llyiahf/vczjk/rs;->OoooOoo(Llyiahf/vczjk/f43;Llyiahf/vczjk/xr1;Llyiahf/vczjk/rl8;Ljava/lang/Object;)Llyiahf/vczjk/gh7;

    iput v1, p0, Llyiahf/vczjk/k52;->OooO0OO:I

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 3

    :cond_0
    iget v0, p0, Llyiahf/vczjk/k52;->OooO0OO:I

    if-lez v0, :cond_1

    add-int/lit8 v1, v0, -0x1

    goto :goto_0

    :cond_1
    const/4 v1, 0x0

    :goto_0
    sget-object v2, Llyiahf/vczjk/k52;->OooO0Oo:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {v2, p0, v0, v1}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->compareAndSet(Ljava/lang/Object;II)Z

    move-result v0

    if-eqz v0, :cond_0

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-nez v1, :cond_2

    iget-object v1, p0, Llyiahf/vczjk/k52;->OooO0O0:Llyiahf/vczjk/jj0;

    sget-object v2, Llyiahf/vczjk/b99;->OooOOO0:Llyiahf/vczjk/b99;

    invoke-interface {v1, v2, p1}, Llyiahf/vczjk/if8;->OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, v1, :cond_2

    return-object p1

    :cond_2
    return-object v0
.end method
