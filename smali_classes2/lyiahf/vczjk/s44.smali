.class public final Llyiahf/vczjk/s44;
.super Llyiahf/vczjk/f84;
.source "SourceFile"


# static fields
.field public static final synthetic OooOOo:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;


# instance fields
.field public final OooOOo0:Llyiahf/vczjk/o00000;

.field private volatile synthetic _invoked$volatile:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    const-class v0, Llyiahf/vczjk/s44;

    const-string v1, "_invoked$volatile"

    invoke-static {v0, v1}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/s44;->OooOOo:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/o00000;)V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/r45;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/s44;->OooOOo0:Llyiahf/vczjk/o00000;

    return-void
.end method


# virtual methods
.method public final OooOO0O()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public final OooOO0o(Ljava/lang/Throwable;)V
    .locals 3

    const/4 v0, 0x1

    sget-object v1, Llyiahf/vczjk/s44;->OooOOo:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    const/4 v2, 0x0

    invoke-virtual {v1, p0, v2, v0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->compareAndSet(Ljava/lang/Object;II)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/s44;->OooOOo0:Llyiahf/vczjk/o00000;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/o00000;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    return-void
.end method
