.class public abstract Llyiahf/vczjk/lj0;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO:Llyiahf/vczjk/h87;

.field public static final OooO00o:Llyiahf/vczjk/kt0;

.field public static final OooO0O0:I

.field public static final OooO0OO:I

.field public static final OooO0Oo:Llyiahf/vczjk/h87;

.field public static final OooO0o:Llyiahf/vczjk/h87;

.field public static final OooO0o0:Llyiahf/vczjk/h87;

.field public static final OooO0oO:Llyiahf/vczjk/h87;

.field public static final OooO0oo:Llyiahf/vczjk/h87;

.field public static final OooOO0:Llyiahf/vczjk/h87;

.field public static final OooOO0O:Llyiahf/vczjk/h87;

.field public static final OooOO0o:Llyiahf/vczjk/h87;

.field public static final OooOOO:Llyiahf/vczjk/h87;

.field public static final OooOOO0:Llyiahf/vczjk/h87;

.field public static final OooOOOO:Llyiahf/vczjk/h87;

.field public static final OooOOOo:Llyiahf/vczjk/h87;

.field public static final OooOOo:Llyiahf/vczjk/h87;

.field public static final OooOOo0:Llyiahf/vczjk/h87;

.field public static final OooOOoo:Llyiahf/vczjk/h87;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    new-instance v0, Llyiahf/vczjk/kt0;

    const-wide/16 v1, -0x1

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/kt0;-><init>(JLlyiahf/vczjk/kt0;Llyiahf/vczjk/jj0;I)V

    sput-object v0, Llyiahf/vczjk/lj0;->OooO00o:Llyiahf/vczjk/kt0;

    const-string v0, "kotlinx.coroutines.bufferedChannel.segmentSize"

    const/16 v1, 0x20

    const/16 v2, 0xc

    invoke-static {v1, v2, v0}, Llyiahf/vczjk/eo6;->OooOoo0(IILjava/lang/String;)I

    move-result v0

    sput v0, Llyiahf/vczjk/lj0;->OooO0O0:I

    const-string v0, "kotlinx.coroutines.bufferedChannel.expandBufferCompletionWaitIterations"

    const/16 v1, 0x2710

    invoke-static {v1, v2, v0}, Llyiahf/vczjk/eo6;->OooOoo0(IILjava/lang/String;)I

    move-result v0

    sput v0, Llyiahf/vczjk/lj0;->OooO0OO:I

    new-instance v0, Llyiahf/vczjk/h87;

    const-string v1, "BUFFERED"

    const/16 v2, 0x8

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/h87;-><init>(Ljava/lang/Object;I)V

    sput-object v0, Llyiahf/vczjk/lj0;->OooO0Oo:Llyiahf/vczjk/h87;

    new-instance v0, Llyiahf/vczjk/h87;

    const-string v1, "SHOULD_BUFFER"

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/h87;-><init>(Ljava/lang/Object;I)V

    sput-object v0, Llyiahf/vczjk/lj0;->OooO0o0:Llyiahf/vczjk/h87;

    new-instance v0, Llyiahf/vczjk/h87;

    const-string v1, "S_RESUMING_BY_RCV"

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/h87;-><init>(Ljava/lang/Object;I)V

    sput-object v0, Llyiahf/vczjk/lj0;->OooO0o:Llyiahf/vczjk/h87;

    new-instance v0, Llyiahf/vczjk/h87;

    const-string v1, "RESUMING_BY_EB"

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/h87;-><init>(Ljava/lang/Object;I)V

    sput-object v0, Llyiahf/vczjk/lj0;->OooO0oO:Llyiahf/vczjk/h87;

    new-instance v0, Llyiahf/vczjk/h87;

    const-string v1, "POISONED"

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/h87;-><init>(Ljava/lang/Object;I)V

    sput-object v0, Llyiahf/vczjk/lj0;->OooO0oo:Llyiahf/vczjk/h87;

    new-instance v0, Llyiahf/vczjk/h87;

    const-string v1, "DONE_RCV"

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/h87;-><init>(Ljava/lang/Object;I)V

    sput-object v0, Llyiahf/vczjk/lj0;->OooO:Llyiahf/vczjk/h87;

    new-instance v0, Llyiahf/vczjk/h87;

    const-string v1, "INTERRUPTED_SEND"

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/h87;-><init>(Ljava/lang/Object;I)V

    sput-object v0, Llyiahf/vczjk/lj0;->OooOO0:Llyiahf/vczjk/h87;

    new-instance v0, Llyiahf/vczjk/h87;

    const-string v1, "INTERRUPTED_RCV"

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/h87;-><init>(Ljava/lang/Object;I)V

    sput-object v0, Llyiahf/vczjk/lj0;->OooOO0O:Llyiahf/vczjk/h87;

    new-instance v0, Llyiahf/vczjk/h87;

    const-string v1, "CHANNEL_CLOSED"

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/h87;-><init>(Ljava/lang/Object;I)V

    sput-object v0, Llyiahf/vczjk/lj0;->OooOO0o:Llyiahf/vczjk/h87;

    new-instance v0, Llyiahf/vczjk/h87;

    const-string v1, "SUSPEND"

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/h87;-><init>(Ljava/lang/Object;I)V

    sput-object v0, Llyiahf/vczjk/lj0;->OooOOO0:Llyiahf/vczjk/h87;

    new-instance v0, Llyiahf/vczjk/h87;

    const-string v1, "SUSPEND_NO_WAITER"

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/h87;-><init>(Ljava/lang/Object;I)V

    sput-object v0, Llyiahf/vczjk/lj0;->OooOOO:Llyiahf/vczjk/h87;

    new-instance v0, Llyiahf/vczjk/h87;

    const-string v1, "FAILED"

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/h87;-><init>(Ljava/lang/Object;I)V

    sput-object v0, Llyiahf/vczjk/lj0;->OooOOOO:Llyiahf/vczjk/h87;

    new-instance v0, Llyiahf/vczjk/h87;

    const-string v1, "NO_RECEIVE_RESULT"

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/h87;-><init>(Ljava/lang/Object;I)V

    sput-object v0, Llyiahf/vczjk/lj0;->OooOOOo:Llyiahf/vczjk/h87;

    new-instance v0, Llyiahf/vczjk/h87;

    const-string v1, "CLOSE_HANDLER_CLOSED"

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/h87;-><init>(Ljava/lang/Object;I)V

    sput-object v0, Llyiahf/vczjk/lj0;->OooOOo0:Llyiahf/vczjk/h87;

    new-instance v0, Llyiahf/vczjk/h87;

    const-string v1, "CLOSE_HANDLER_INVOKED"

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/h87;-><init>(Ljava/lang/Object;I)V

    sput-object v0, Llyiahf/vczjk/lj0;->OooOOo:Llyiahf/vczjk/h87;

    new-instance v0, Llyiahf/vczjk/h87;

    const-string v1, "NO_CLOSE_CAUSE"

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/h87;-><init>(Ljava/lang/Object;I)V

    sput-object v0, Llyiahf/vczjk/lj0;->OooOOoo:Llyiahf/vczjk/h87;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/wp0;Ljava/lang/Object;Llyiahf/vczjk/bf3;)Z
    .locals 0

    invoke-interface {p0, p1, p2}, Llyiahf/vczjk/wp0;->OooOO0O(Ljava/lang/Object;Llyiahf/vczjk/bf3;)Llyiahf/vczjk/h87;

    move-result-object p1

    if-eqz p1, :cond_0

    invoke-interface {p0, p1}, Llyiahf/vczjk/wp0;->OooOOOo(Ljava/lang/Object;)V

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method
