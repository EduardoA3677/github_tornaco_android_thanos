.class public final Llyiahf/vczjk/q44;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public OooO:Llyiahf/vczjk/gq5;

.field public final OooO00o:Llyiahf/vczjk/ru7;

.field public final OooO0O0:[Ljava/lang/String;

.field public final OooO0OO:Llyiahf/vczjk/b1a;

.field public final OooO0Oo:Ljava/util/LinkedHashMap;

.field public final OooO0o:Llyiahf/vczjk/n44;

.field public final OooO0o0:Ljava/util/concurrent/locks/ReentrantLock;

.field public final OooO0oO:Llyiahf/vczjk/n44;

.field public OooO0oo:Landroid/content/Intent;

.field public final OooOO0:Ljava/lang/Object;


# direct methods
.method public varargs constructor <init>(Llyiahf/vczjk/ru7;Ljava/util/HashMap;Ljava/util/HashMap;[Ljava/lang/String;)V
    .locals 11

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/q44;->OooO00o:Llyiahf/vczjk/ru7;

    move-object v8, p4

    iput-object v8, p0, Llyiahf/vczjk/q44;->OooO0O0:[Ljava/lang/String;

    new-instance v9, Llyiahf/vczjk/b1a;

    invoke-virtual {p1}, Llyiahf/vczjk/ru7;->getUseTempTrackingTable$room_runtime_release()Z

    move-result v10

    new-instance v0, Llyiahf/vczjk/o00000;

    const-class v3, Llyiahf/vczjk/q44;

    const-string v4, "notifyInvalidatedObservers"

    const/4 v1, 0x1

    const-string v5, "notifyInvalidatedObservers(Ljava/util/Set;)V"

    const/4 v6, 0x0

    const/4 v7, 0x6

    move-object v2, p0

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/o00000;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move-object v6, v0

    move-object v4, v8

    move-object v0, v9

    move v5, v10

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/b1a;-><init>(Llyiahf/vczjk/ru7;Ljava/util/HashMap;Ljava/util/HashMap;[Ljava/lang/String;ZLlyiahf/vczjk/o00000;)V

    iput-object v0, p0, Llyiahf/vczjk/q44;->OooO0OO:Llyiahf/vczjk/b1a;

    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    iput-object v1, p0, Llyiahf/vczjk/q44;->OooO0Oo:Ljava/util/LinkedHashMap;

    new-instance v1, Ljava/util/concurrent/locks/ReentrantLock;

    invoke-direct {v1}, Ljava/util/concurrent/locks/ReentrantLock;-><init>()V

    iput-object v1, p0, Llyiahf/vczjk/q44;->OooO0o0:Ljava/util/concurrent/locks/ReentrantLock;

    new-instance v1, Llyiahf/vczjk/n44;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/n44;-><init>(Llyiahf/vczjk/q44;I)V

    iput-object v1, p0, Llyiahf/vczjk/q44;->OooO0o:Llyiahf/vczjk/n44;

    new-instance v1, Llyiahf/vczjk/n44;

    const/4 v2, 0x1

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/n44;-><init>(Llyiahf/vczjk/q44;I)V

    iput-object v1, p0, Llyiahf/vczjk/q44;->OooO0oO:Llyiahf/vczjk/n44;

    new-instance v1, Ljava/util/IdentityHashMap;

    invoke-direct {v1}, Ljava/util/IdentityHashMap;-><init>()V

    invoke-static {v1}, Ljava/util/Collections;->newSetFromMap(Ljava/util/Map;)Ljava/util/Set;

    move-result-object v1

    const-string v2, "newSetFromMap(...)"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Ljava/lang/Object;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    iput-object v1, p0, Llyiahf/vczjk/q44;->OooOO0:Ljava/lang/Object;

    new-instance v1, Llyiahf/vczjk/n44;

    const/4 v2, 0x2

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/n44;-><init>(Llyiahf/vczjk/q44;I)V

    iput-object v1, v0, Llyiahf/vczjk/b1a;->OooOO0O:Llyiahf/vczjk/le3;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/eb9;)Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/q44;->OooO00o:Llyiahf/vczjk/ru7;

    invoke-virtual {v0}, Llyiahf/vczjk/ru7;->inCompatibilityMode$room_runtime_release()Z

    move-result v1

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-eqz v1, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/ru7;->isOpenInternal()Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/q44;->OooO0OO:Llyiahf/vczjk/b1a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/b1a;->OooO0o(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, v0, :cond_1

    return-object p1

    :cond_1
    :goto_0
    return-object v2
.end method
