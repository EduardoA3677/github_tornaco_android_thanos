.class public final Llyiahf/vczjk/ud0;
.super Llyiahf/vczjk/o000O000;
.source "SourceFile"


# instance fields
.field public final OooOOOo:Ljava/lang/Thread;

.field public final OooOOo0:Llyiahf/vczjk/pr2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/or1;Ljava/lang/Thread;Llyiahf/vczjk/pr2;)V
    .locals 1

    const/4 v0, 0x1

    invoke-direct {p0, p1, v0}, Llyiahf/vczjk/o000O000;-><init>(Llyiahf/vczjk/or1;Z)V

    iput-object p2, p0, Llyiahf/vczjk/ud0;->OooOOOo:Ljava/lang/Thread;

    iput-object p3, p0, Llyiahf/vczjk/ud0;->OooOOo0:Llyiahf/vczjk/pr2;

    return-void
.end method


# virtual methods
.method public final OooOO0(Ljava/lang/Object;)V
    .locals 1

    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/ud0;->OooOOOo:Ljava/lang/Thread;

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-nez p1, :cond_0

    invoke-static {v0}, Ljava/util/concurrent/locks/LockSupport;->unpark(Ljava/lang/Thread;)V

    :cond_0
    return-void
.end method
