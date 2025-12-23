.class public final synthetic Llyiahf/vczjk/kt5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/lt5;

.field public final synthetic OooOOO0:Llyiahf/vczjk/mt5;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/mt5;Llyiahf/vczjk/lt5;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/kt5;->OooOOO0:Llyiahf/vczjk/mt5;

    iput-object p2, p0, Llyiahf/vczjk/kt5;->OooOOO:Llyiahf/vczjk/lt5;

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Ljava/lang/Throwable;

    check-cast p2, Llyiahf/vczjk/z8a;

    check-cast p3, Llyiahf/vczjk/or1;

    sget-object p1, Llyiahf/vczjk/mt5;->OooOo00:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    iget-object p2, p0, Llyiahf/vczjk/kt5;->OooOOO:Llyiahf/vczjk/lt5;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object p2, p0, Llyiahf/vczjk/kt5;->OooOOO0:Llyiahf/vczjk/mt5;

    const/4 p3, 0x0

    invoke-virtual {p1, p2, p3}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {p2, p3}, Llyiahf/vczjk/mt5;->OooO0Oo(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
