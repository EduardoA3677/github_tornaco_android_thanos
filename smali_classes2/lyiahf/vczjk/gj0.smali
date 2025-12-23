.class public final synthetic Llyiahf/vczjk/gj0;
.super Llyiahf/vczjk/wf3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/gj0;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    new-instance v0, Llyiahf/vczjk/gj0;

    const-string v4, "processResultSelectReceiveCatching(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;"

    const/4 v5, 0x0

    const/4 v1, 0x3

    const-class v2, Llyiahf/vczjk/jj0;

    const-string v3, "processResultSelectReceiveCatching"

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/wf3;-><init>(ILjava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sput-object v0, Llyiahf/vczjk/gj0;->OooOOO:Llyiahf/vczjk/gj0;

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/jj0;

    sget-object p2, Llyiahf/vczjk/jj0;->OooOOO:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object p2, Llyiahf/vczjk/lj0;->OooOO0o:Llyiahf/vczjk/h87;

    if-ne p3, p2, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/jj0;->OooOOo()Ljava/lang/Throwable;

    move-result-object p1

    new-instance p3, Llyiahf/vczjk/ht0;

    invoke-direct {p3, p1}, Llyiahf/vczjk/ht0;-><init>(Ljava/lang/Throwable;)V

    :cond_0
    new-instance p1, Llyiahf/vczjk/jt0;

    invoke-direct {p1, p3}, Llyiahf/vczjk/jt0;-><init>(Ljava/lang/Object;)V

    return-object p1
.end method
