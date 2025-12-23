.class public final Llyiahf/vczjk/ai7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/sl1;


# static fields
.field public static final synthetic OooOOO:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

.field public static final synthetic OooOOO0:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;


# instance fields
.field public final OooO:Llyiahf/vczjk/gh7;

.field public final OooO00o:Llyiahf/vczjk/oi7;

.field public final OooO0O0:Llyiahf/vczjk/to1;

.field public final OooO0OO:Llyiahf/vczjk/x74;

.field public final OooO0Oo:Llyiahf/vczjk/jj0;

.field public final OooO0o:Llyiahf/vczjk/s29;

.field public volatile synthetic OooO0o0:I

.field public final OooO0oO:Llyiahf/vczjk/jj0;

.field public volatile synthetic OooO0oo:I

.field public final OooOO0:Llyiahf/vczjk/ll7;

.field public final OooOO0O:Llyiahf/vczjk/jl7;

.field public final OooOO0o:Llyiahf/vczjk/tl1;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    const-string v0, "OooO0o0"

    const-class v1, Llyiahf/vczjk/ai7;

    invoke-static {v1, v0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/ai7;->OooOOO0:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    const-string v0, "OooO0oo"

    invoke-static {v1, v0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/ai7;->OooOOO:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/cm4;Llyiahf/vczjk/to1;Llyiahf/vczjk/oi7;)V
    .locals 9

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p3, p0, Llyiahf/vczjk/ai7;->OooO00o:Llyiahf/vczjk/oi7;

    iget-object v0, p3, Llyiahf/vczjk/oi7;->OooO0OO:Llyiahf/vczjk/qr1;

    new-instance v1, Llyiahf/vczjk/to1;

    iget-object p2, p2, Llyiahf/vczjk/to1;->OooOOO0:Llyiahf/vczjk/or1;

    invoke-interface {p2, v0}, Llyiahf/vczjk/or1;->OooOOOO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object p2

    invoke-direct {v1, p2}, Llyiahf/vczjk/to1;-><init>(Llyiahf/vczjk/or1;)V

    iput-object v1, p0, Llyiahf/vczjk/ai7;->OooO0O0:Llyiahf/vczjk/to1;

    sget-object v0, Llyiahf/vczjk/ws7;->OooOOo0:Llyiahf/vczjk/ws7;

    invoke-interface {p2, v0}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/v74;

    new-instance v0, Llyiahf/vczjk/x74;

    invoke-direct {v0, p2}, Llyiahf/vczjk/x74;-><init>(Llyiahf/vczjk/v74;)V

    iput-object v0, p0, Llyiahf/vczjk/ai7;->OooO0OO:Llyiahf/vczjk/x74;

    const p2, 0x7fffffff

    const/4 v0, 0x0

    const/4 v2, 0x6

    invoke-static {p2, v2, v0}, Llyiahf/vczjk/tg0;->OooO0o0(IILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jj0;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/ai7;->OooO0Oo:Llyiahf/vczjk/jj0;

    const/4 p2, 0x0

    iput p2, p0, Llyiahf/vczjk/ai7;->OooO0o0:I

    new-instance v7, Llyiahf/vczjk/k52;

    iget-wide v3, p3, Llyiahf/vczjk/oi7;->OooO0o0:J

    invoke-direct {v7, v1, v3, v4}, Llyiahf/vczjk/k52;-><init>(Llyiahf/vczjk/to1;J)V

    invoke-static {p1}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ai7;->OooO0o:Llyiahf/vczjk/s29;

    iget v1, p3, Llyiahf/vczjk/oi7;->OooO00o:I

    invoke-static {v1, v2, v0}, Llyiahf/vczjk/tg0;->OooO0o0(IILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jj0;

    move-result-object v1

    iput-object v1, p0, Llyiahf/vczjk/ai7;->OooO0oO:Llyiahf/vczjk/jj0;

    iput p2, p0, Llyiahf/vczjk/ai7;->OooO0oo:I

    new-instance v8, Llyiahf/vczjk/gh7;

    invoke-direct {v8, p1}, Llyiahf/vczjk/gh7;-><init>(Llyiahf/vczjk/rs5;)V

    iput-object v8, p0, Llyiahf/vczjk/ai7;->OooO:Llyiahf/vczjk/gh7;

    new-instance v2, Llyiahf/vczjk/ss0;

    invoke-direct {v2, v1, p2}, Llyiahf/vczjk/ss0;-><init>(Llyiahf/vczjk/ui7;Z)V

    new-instance p2, Llyiahf/vczjk/ll7;

    invoke-direct {p2, v7, p1}, Llyiahf/vczjk/ll7;-><init>(Llyiahf/vczjk/w89;Llyiahf/vczjk/s29;)V

    iput-object p2, p0, Llyiahf/vczjk/ai7;->OooOO0:Llyiahf/vczjk/ll7;

    new-instance p1, Llyiahf/vczjk/jl7;

    invoke-direct {p1, v7, v2}, Llyiahf/vczjk/jl7;-><init>(Llyiahf/vczjk/w89;Llyiahf/vczjk/ss0;)V

    iput-object p1, p0, Llyiahf/vczjk/ai7;->OooOO0O:Llyiahf/vczjk/jl7;

    new-instance v3, Llyiahf/vczjk/tl1;

    new-instance v5, Llyiahf/vczjk/yh7;

    invoke-direct {v5, p0, v0}, Llyiahf/vczjk/yh7;-><init>(Llyiahf/vczjk/ai7;Llyiahf/vczjk/yo1;)V

    new-instance v6, Llyiahf/vczjk/zh7;

    invoke-direct {v6, p0, v0}, Llyiahf/vczjk/zh7;-><init>(Llyiahf/vczjk/ai7;Llyiahf/vczjk/yo1;)V

    move-object v4, p3

    invoke-direct/range {v3 .. v8}, Llyiahf/vczjk/tl1;-><init>(Llyiahf/vczjk/oi7;Llyiahf/vczjk/yh7;Llyiahf/vczjk/zh7;Llyiahf/vczjk/w89;Llyiahf/vczjk/gh7;)V

    iput-object v3, p0, Llyiahf/vczjk/ai7;->OooOO0o:Llyiahf/vczjk/tl1;

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/f43;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ai7;->OooOO0O:Llyiahf/vczjk/jl7;

    return-object v0
.end method

.method public final OooO0O0()Llyiahf/vczjk/q29;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ai7;->OooO:Llyiahf/vczjk/gh7;

    return-object v0
.end method

.method public final OooO0OO(Llyiahf/vczjk/wl1;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 9

    instance-of v0, p2, Llyiahf/vczjk/xh7;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/xh7;

    iget v1, v0, Llyiahf/vczjk/xh7;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/xh7;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/xh7;

    check-cast p2, Llyiahf/vczjk/zo1;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/xh7;-><init>(Llyiahf/vczjk/ai7;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/xh7;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/xh7;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    iget-object p1, v0, Llyiahf/vczjk/xh7;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/b61;

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object p1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    sget-object p2, Llyiahf/vczjk/ai7;->OooOOO0:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    const/4 v2, 0x0

    invoke-virtual {p2, p0, v2, v3}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->compareAndSet(Ljava/lang/Object;II)Z

    move-result p2

    if-eqz p2, :cond_3

    sget-object p2, Llyiahf/vczjk/kc2;->OooO0O0:Llyiahf/vczjk/h8a;

    new-instance v4, Llyiahf/vczjk/th7;

    const/4 v5, 0x0

    invoke-direct {v4, p0, v5}, Llyiahf/vczjk/th7;-><init>(Llyiahf/vczjk/ai7;Llyiahf/vczjk/yo1;)V

    sget-object v6, Llyiahf/vczjk/aj0;->OooOOO0:Llyiahf/vczjk/aj0;

    sget-object v7, Llyiahf/vczjk/as1;->OooOOO0:Llyiahf/vczjk/as1;

    const/4 v8, 0x4

    invoke-static {v2, v8, v6}, Llyiahf/vczjk/tg0;->OooO0o0(IILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jj0;

    move-result-object v2

    iget-object v6, p0, Llyiahf/vczjk/ai7;->OooO0O0:Llyiahf/vczjk/to1;

    invoke-static {v6, p2}, Llyiahf/vczjk/t51;->Oooo(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object p2

    new-instance v8, Llyiahf/vczjk/r77;

    invoke-direct {v8, p2, v2}, Llyiahf/vczjk/r77;-><init>(Llyiahf/vczjk/or1;Llyiahf/vczjk/jj0;)V

    invoke-virtual {v8, v7, v8, v4}, Llyiahf/vczjk/o000O000;->Oooooo(Llyiahf/vczjk/as1;Llyiahf/vczjk/o000O000;Llyiahf/vczjk/ze3;)V

    new-instance p2, Llyiahf/vczjk/tr1;

    const-string v2, "orbit-event-loop"

    invoke-direct {p2, v2}, Llyiahf/vczjk/tr1;-><init>(Ljava/lang/String;)V

    new-instance v2, Llyiahf/vczjk/wh7;

    invoke-direct {v2, p0, v5}, Llyiahf/vczjk/wh7;-><init>(Llyiahf/vczjk/ai7;Llyiahf/vczjk/yo1;)V

    const/4 v4, 0x2

    invoke-static {v6, p2, v5, v2, v4}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_3
    iget-object p2, p0, Llyiahf/vczjk/ai7;->OooO0OO:Llyiahf/vczjk/x74;

    new-instance v2, Llyiahf/vczjk/x74;

    invoke-direct {v2, p2}, Llyiahf/vczjk/x74;-><init>(Llyiahf/vczjk/v74;)V

    iget-object p2, p0, Llyiahf/vczjk/ai7;->OooO0Oo:Llyiahf/vczjk/jj0;

    new-instance v4, Llyiahf/vczjk/xn6;

    invoke-direct {v4, v2, p1}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    iput-object v2, v0, Llyiahf/vczjk/xh7;->L$0:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/xh7;->label:I

    invoke-interface {p2, v4, v0}, Llyiahf/vczjk/if8;->OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_4

    return-object v1

    :cond_4
    return-object v2
.end method

.method public final OooO0Oo()Llyiahf/vczjk/q29;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ai7;->OooOO0:Llyiahf/vczjk/ll7;

    return-object v0
.end method
