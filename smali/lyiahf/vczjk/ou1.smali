.class public final Llyiahf/vczjk/ou1;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Z

.field public final OooO0O0:Ljava/util/concurrent/atomic/AtomicReference;

.field public final OooO0OO:Llyiahf/vczjk/lr5;


# direct methods
.method public constructor <init>(Z)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Llyiahf/vczjk/ou1;->OooO00o:Z

    new-instance p1, Ljava/util/concurrent/atomic/AtomicReference;

    const/4 v0, 0x0

    invoke-direct {p1, v0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    iput-object p1, p0, Llyiahf/vczjk/ou1;->OooO0O0:Ljava/util/concurrent/atomic/AtomicReference;

    const/4 p1, 0x0

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooO0o(F)Llyiahf/vczjk/lr5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ou1;->OooO0OO:Llyiahf/vczjk/lr5;

    return-void
.end method
