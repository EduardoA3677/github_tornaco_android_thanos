.class public final Llyiahf/vczjk/qx7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/dy6;
.implements Llyiahf/vczjk/tp8;
.implements Llyiahf/vczjk/ad8;


# instance fields
.field public final OooOOO:Ljava/lang/Object;

.field public final OooOOO0:Ljava/lang/Object;


# direct methods
.method public constructor <init>(I)V
    .locals 1

    packed-switch p1, :pswitch_data_0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-direct {p1}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/qx7;->OooOOO0:Ljava/lang/Object;

    new-instance p1, Ljava/lang/ref/ReferenceQueue;

    invoke-direct {p1}, Ljava/lang/ref/ReferenceQueue;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/qx7;->OooOOO:Ljava/lang/Object;

    return-void

    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, Llyiahf/vczjk/ws5;

    const/16 v0, 0x10

    new-array v0, v0, [Ljava/lang/ref/Reference;

    invoke-direct {p1, v0}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    iput-object p1, p0, Llyiahf/vczjk/qx7;->OooOOO0:Ljava/lang/Object;

    new-instance p1, Ljava/lang/ref/ReferenceQueue;

    invoke-direct {p1}, Ljava/lang/ref/ReferenceQueue;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/qx7;->OooOOO:Ljava/lang/Object;

    return-void

    :pswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, Llyiahf/vczjk/ao8;

    const/4 v0, 0x0

    invoke-direct {p1, v0}, Llyiahf/vczjk/ao8;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/qx7;->OooOOO0:Ljava/lang/Object;

    new-instance p1, Llyiahf/vczjk/i65;

    const/4 v0, 0x0

    invoke-direct {p1, v0}, Llyiahf/vczjk/i65;-><init>(Ljava/lang/Object;)V

    iput-object p1, p0, Llyiahf/vczjk/qx7;->OooOOO:Ljava/lang/Object;

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x9
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public constructor <init>(Lgithub/tornaco/android/thanos/core/persist/StringSetRepo;Llyiahf/vczjk/fo9;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/qx7;->OooOOO0:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/qx7;->OooOOO:Ljava/lang/Object;

    new-instance p1, Llyiahf/vczjk/z19;

    invoke-direct {p1, p0}, Llyiahf/vczjk/z19;-><init>(Llyiahf/vczjk/qx7;)V

    iget-object p2, p2, Llyiahf/vczjk/fo9;->OooOo00:Llyiahf/vczjk/mf7;

    sget-object v0, Lgithub/tornaco/android/thanos/core/push/PushChannel;->FCM_GCM:Lgithub/tornaco/android/thanos/core/push/PushChannel;

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/push/PushChannel;->getChannelId()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p2, v0, p1}, Llyiahf/vczjk/mf7;->registerChannelHandler(Ljava/lang/String;Lgithub/tornaco/android/thanos/core/push/IChannelHandler;)V

    return-void
.end method

.method public constructor <init>(Lgithub/tornaco/android/thanos/db/profile/RuleDb;Llyiahf/vczjk/o27;)V
    .locals 1

    const-string v0, "perf"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/qx7;->OooOOO0:Ljava/lang/Object;

    new-instance p1, Llyiahf/vczjk/a27;

    sget-object p2, Llyiahf/vczjk/sp3;->OooOOOO:Llyiahf/vczjk/sp3;

    invoke-direct {p1, p2}, Llyiahf/vczjk/a27;-><init>(Llyiahf/vczjk/h52;)V

    iput-object p1, p0, Llyiahf/vczjk/qx7;->OooOOO:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/qx7;->OooOOO0:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/qx7;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/dv1;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/qx7;->OooOOO:Ljava/lang/Object;

    new-instance p1, Llyiahf/vczjk/ra;

    const/16 v0, 0x1d

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/ra;-><init>(Ljava/lang/Object;I)V

    iput-object p1, p0, Llyiahf/vczjk/qx7;->OooOOO0:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/np8;Llyiahf/vczjk/tp8;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/qx7;->OooOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/qx7;->OooOOO0:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/t92;Llyiahf/vczjk/ol0;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    if-eqz p1, :cond_0

    iput-object p1, p0, Llyiahf/vczjk/qx7;->OooOOO0:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/qx7;->OooOOO:Ljava/lang/Object;

    return-void

    :cond_0
    new-instance p1, Ljava/lang/NullPointerException;

    const-string p2, "file == null"

    invoke-direct {p1, p2}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public constructor <init>(Llyiahf/vczjk/xj0;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, Llyiahf/vczjk/q45;

    const-string v0, "Type parameter upper bound erasure results"

    invoke-direct {p1, v0}, Llyiahf/vczjk/q45;-><init>(Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/e19;

    const/4 v1, 0x3

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/e19;-><init>(Ljava/lang/Object;I)V

    invoke-static {v0}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/qx7;->OooOOO0:Ljava/lang/Object;

    new-instance v0, Llyiahf/vczjk/oo000o;

    const/16 v1, 0x1b

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/oo000o;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p1, v0}, Llyiahf/vczjk/q45;->OooO0O0(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/l45;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/qx7;->OooOOO:Ljava/lang/Object;

    return-void
.end method

.method public static OooO(Llyiahf/vczjk/t92;Llyiahf/vczjk/hj1;)V
    .locals 3

    instance-of v0, p1, Llyiahf/vczjk/gt1;

    if-eqz v0, :cond_1

    check-cast p1, Llyiahf/vczjk/gt1;

    iget-object p1, p1, Llyiahf/vczjk/gt1;->OooOOO0:Llyiahf/vczjk/ft1;

    iget-object v0, p1, Llyiahf/vczjk/x13;->OooOOO:[Ljava/lang/Object;

    array-length v0, v0

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_0

    invoke-virtual {p1, v1}, Llyiahf/vczjk/x13;->OooO0o0(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/hj1;

    invoke-static {p0, v2}, Llyiahf/vczjk/qx7;->OooO(Llyiahf/vczjk/t92;Llyiahf/vczjk/hj1;)V

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_0
    return-void

    :cond_1
    invoke-virtual {p0, p1}, Llyiahf/vczjk/t92;->OooO00o(Llyiahf/vczjk/hj1;)V

    return-void
.end method

.method public static OooOO0o(Ljava/lang/String;Ljava/lang/String;)[Ljava/lang/String;
    .locals 4

    const-string v0, "DENY * "

    invoke-static {v0, p0}, Llyiahf/vczjk/u81;->OooOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    const-string v1, "DENY "

    const-string v2, " *"

    invoke-static {v1, p1, v2}, Llyiahf/vczjk/u81;->OooOOO0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    const-string v3, " "

    invoke-static {v1, p1, v3, p0}, Llyiahf/vczjk/ii5;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    filled-new-array {v0, v2, p0}, [Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static OooOOO(Ljava/lang/String;)[Ljava/lang/String;
    .locals 3

    const-string v0, "ALLOW GCM "

    invoke-static {v0, p0}, Llyiahf/vczjk/u81;->OooOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    const-string v1, "ALLOW FCM "

    invoke-static {v1, p0}, Llyiahf/vczjk/u81;->OooOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    const-string v1, "ALLOW FCM *"

    const-string v2, "ALLOW GCM *"

    filled-new-array {v0, v2, p0, v1}, [Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static OooOOO0(Landroid/content/ComponentName;Ljava/lang/String;Ljava/lang/String;)[Ljava/lang/String;
    .locals 5

    const-string v0, "ALLOW * "

    invoke-static {v0, p1}, Llyiahf/vczjk/u81;->OooOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    const-string v1, "ALLOW "

    const-string v2, " *"

    invoke-static {v1, p2, v2}, Llyiahf/vczjk/u81;->OooOOO0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    const-string v3, " "

    invoke-static {v1, p2, v3, p1}, Llyiahf/vczjk/ii5;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    const-string v4, "ALLOW THIS THIS"

    filled-new-array {v4, v0, v2, p1}, [Ljava/lang/String;

    move-result-object p1

    if-nez p0, :cond_0

    return-object p1

    :cond_0
    invoke-virtual {p0}, Landroid/content/ComponentName;->flattenToString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v1, p2, v3, v0}, Llyiahf/vczjk/ii5;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p0}, Landroid/content/ComponentName;->flattenToShortString()Ljava/lang/String;

    move-result-object p0

    invoke-static {v1, p2, v3, p0}, Llyiahf/vczjk/ii5;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    filled-new-array {v0, p0}, [Ljava/lang/String;

    move-result-object p0

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p2

    invoke-virtual {p2}, Ljava/lang/Class;->getComponentType()Ljava/lang/Class;

    move-result-object p2

    const/4 v0, 0x6

    invoke-static {p2, v0}, Ljava/lang/reflect/Array;->newInstance(Ljava/lang/Class;I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Ljava/lang/Object;

    const/4 v1, 0x0

    const/4 v2, 0x4

    invoke-static {p1, v1, v0, v1, v2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    const/4 p1, 0x2

    :try_start_0
    invoke-static {p0, v1, v0, v2, p1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V
    :try_end_0
    .catch Ljava/lang/ArrayStoreException; {:try_start_0 .. :try_end_0} :catch_0

    check-cast v0, [Ljava/lang/String;

    return-object v0

    :catch_0
    move-exception p1

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p0

    invoke-virtual {p0}, Ljava/lang/Class;->getComponentType()Ljava/lang/Class;

    move-result-object p0

    invoke-virtual {p2, p0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v0

    if-nez v0, :cond_1

    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p0

    invoke-virtual {p2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p2

    const-string v1, "Cannot store "

    const-string v2, " in an array of "

    invoke-static {v1, p0, v2, p2}, Llyiahf/vczjk/ii5;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v0

    :cond_1
    throw p1
.end method

.method public static OooOOOO(Llyiahf/vczjk/hj1;)I
    .locals 1

    instance-of v0, p0, Llyiahf/vczjk/it1;

    if-eqz v0, :cond_0

    const/4 p0, 0x0

    return p0

    :cond_0
    instance-of v0, p0, Llyiahf/vczjk/yt1;

    if-eqz v0, :cond_1

    const/4 p0, 0x2

    return p0

    :cond_1
    instance-of v0, p0, Llyiahf/vczjk/jt1;

    if-eqz v0, :cond_2

    const/4 p0, 0x3

    return p0

    :cond_2
    instance-of v0, p0, Llyiahf/vczjk/pt1;

    if-eqz v0, :cond_3

    const/4 p0, 0x4

    return p0

    :cond_3
    instance-of v0, p0, Llyiahf/vczjk/ut1;

    if-eqz v0, :cond_4

    const/4 p0, 0x6

    return p0

    :cond_4
    instance-of v0, p0, Llyiahf/vczjk/mt1;

    if-eqz v0, :cond_5

    const/16 p0, 0x10

    return p0

    :cond_5
    instance-of v0, p0, Llyiahf/vczjk/kt1;

    if-eqz v0, :cond_6

    const/16 p0, 0x11

    return p0

    :cond_6
    instance-of v0, p0, Llyiahf/vczjk/zt1;

    if-eqz v0, :cond_7

    const/16 p0, 0x17

    return p0

    :cond_7
    instance-of v0, p0, Llyiahf/vczjk/au1;

    if-eqz v0, :cond_8

    const/16 p0, 0x18

    return p0

    :cond_8
    instance-of v0, p0, Llyiahf/vczjk/lt1;

    if-eqz v0, :cond_9

    const/16 p0, 0x19

    return p0

    :cond_9
    instance-of v0, p0, Llyiahf/vczjk/wt1;

    if-eqz v0, :cond_a

    const/16 p0, 0x1a

    return p0

    :cond_a
    instance-of v0, p0, Llyiahf/vczjk/gt1;

    if-eqz v0, :cond_b

    const/16 p0, 0x1c

    return p0

    :cond_b
    instance-of v0, p0, Llyiahf/vczjk/qt1;

    if-eqz v0, :cond_c

    const/16 p0, 0x1e

    return p0

    :cond_c
    instance-of p0, p0, Llyiahf/vczjk/ht1;

    if-eqz p0, :cond_d

    const/16 p0, 0x1f

    return p0

    :cond_d
    new-instance p0, Ljava/lang/RuntimeException;

    const-string v0, "Shouldn\'t happen"

    invoke-direct {p0, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    throw p0
.end method


# virtual methods
.method public OooO00o(FF)J
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/qx7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, [F

    const/4 v1, 0x0

    aput p1, v0, v1

    const/4 p1, 0x1

    aput p2, v0, p1

    iget-object p2, p0, Llyiahf/vczjk/qx7;->OooOOO:Ljava/lang/Object;

    check-cast p2, Landroid/graphics/Matrix;

    invoke-virtual {p2, v0}, Landroid/graphics/Matrix;->mapPoints([F)V

    aget p2, v0, v1

    aget p1, v0, p1

    invoke-static {p2, p1}, Llyiahf/vczjk/v23;->OooO00o(FF)J

    move-result-wide p1

    return-wide p1
.end method

.method public OooO0O0(Llyiahf/vczjk/nc2;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/qx7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/tp8;

    invoke-interface {v0, p1}, Llyiahf/vczjk/tp8;->OooO0O0(Llyiahf/vczjk/nc2;)V

    return-void
.end method

.method public OooO0OO(Ljava/lang/Throwable;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/qx7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/tp8;

    invoke-interface {v0, p1}, Llyiahf/vczjk/tp8;->OooO0OO(Ljava/lang/Throwable;)V

    return-void
.end method

.method public OooO0Oo(I)I
    .locals 3

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/qx7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/n11;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/n11;->OooOo0O(I)I

    move-result p1

    const/4 v0, -0x1

    if-eq p1, v0, :cond_2

    iget-object v1, p0, Llyiahf/vczjk/qx7;->OooOOO0:Ljava/lang/Object;

    check-cast v1, Ljava/lang/CharSequence;

    invoke-interface {v1}, Ljava/lang/CharSequence;->length()I

    move-result v2

    if-ne p1, v2, :cond_1

    goto :goto_0

    :cond_1
    invoke-interface {v1, p1}, Ljava/lang/CharSequence;->charAt(I)C

    move-result v0

    invoke-static {v0}, Ljava/lang/Character;->isWhitespace(C)Z

    move-result v0

    if-nez v0, :cond_0

    return p1

    :cond_2
    :goto_0
    return v0
.end method

.method public OooO0o(I)I
    .locals 2

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/qx7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/n11;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/n11;->OooOo0o(I)I

    move-result p1

    const/4 v0, -0x1

    if-eq p1, v0, :cond_1

    if-eqz p1, :cond_1

    add-int/lit8 v0, p1, -0x1

    iget-object v1, p0, Llyiahf/vczjk/qx7;->OooOOO0:Ljava/lang/Object;

    check-cast v1, Ljava/lang/CharSequence;

    invoke-interface {v1, v0}, Ljava/lang/CharSequence;->charAt(I)C

    move-result v0

    invoke-static {v0}, Ljava/lang/Character;->isWhitespace(C)Z

    move-result v0

    if-nez v0, :cond_0

    return p1

    :cond_1
    return v0
.end method

.method public OooO0o0(Ljava/lang/Object;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/qx7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/tp8;

    :try_start_0
    iget-object v1, p0, Llyiahf/vczjk/qx7;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/np8;

    iget-object v1, v1, Llyiahf/vczjk/np8;->OooOo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/nl1;

    invoke-interface {v1, p1}, Llyiahf/vczjk/nl1;->accept(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-interface {v0, p1}, Llyiahf/vczjk/tp8;->OooO0o0(Ljava/lang/Object;)V

    return-void

    :catchall_0
    move-exception p1

    invoke-static {p1}, Llyiahf/vczjk/vc6;->Oooo(Ljava/lang/Throwable;)V

    invoke-interface {v0, p1}, Llyiahf/vczjk/tp8;->OooO0OO(Ljava/lang/Throwable;)V

    return-void
.end method

.method public OooO0oO(I)I
    .locals 1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/qx7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/n11;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/n11;->OooOo0o(I)I

    move-result p1

    const/4 v0, -0x1

    if-ne p1, v0, :cond_1

    return v0

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/qx7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Ljava/lang/CharSequence;

    invoke-interface {v0, p1}, Ljava/lang/CharSequence;->charAt(I)C

    move-result v0

    invoke-static {v0}, Ljava/lang/Character;->isWhitespace(C)Z

    move-result v0

    if-nez v0, :cond_0

    return p1
.end method

.method public OooO0oo(I)I
    .locals 2

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/qx7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/n11;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/n11;->OooOo0O(I)I

    move-result p1

    const/4 v0, -0x1

    if-ne p1, v0, :cond_1

    return v0

    :cond_1
    add-int/lit8 v0, p1, -0x1

    iget-object v1, p0, Llyiahf/vczjk/qx7;->OooOOO0:Ljava/lang/Object;

    check-cast v1, Ljava/lang/CharSequence;

    invoke-interface {v1, v0}, Ljava/lang/CharSequence;->charAt(I)C

    move-result v0

    invoke-static {v0}, Ljava/lang/Character;->isWhitespace(C)Z

    move-result v0

    if-nez v0, :cond_0

    return p1
.end method

.method public OooOO0(Landroidx/recyclerview/widget/o000oOoO;Llyiahf/vczjk/yu2;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/qx7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ao8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ao8;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/sga;

    if-nez v1, :cond_0

    invoke-static {}, Llyiahf/vczjk/sga;->OooO00o()Llyiahf/vczjk/sga;

    move-result-object v1

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/ao8;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    iput-object p2, v1, Llyiahf/vczjk/sga;->OooO0OO:Llyiahf/vczjk/yu2;

    iget p1, v1, Llyiahf/vczjk/sga;->OooO00o:I

    or-int/lit8 p1, p1, 0x8

    iput p1, v1, Llyiahf/vczjk/sga;->OooO00o:I

    return-void
.end method

.method public OooOO0O(Landroid/content/Intent;Landroid/content/ComponentName;Ljava/lang/String;Ljava/lang/String;)Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;
    .locals 5

    const/4 v0, 0x0

    iget-object v1, p0, Llyiahf/vczjk/qx7;->OooOOO0:Ljava/lang/Object;

    check-cast v1, Lgithub/tornaco/android/thanos/core/persist/StringSetRepo;

    if-nez v1, :cond_0

    const-string p1, "ruleRepo is null..."

    invoke-static {p1}, Llyiahf/vczjk/zsa;->Oooo0O0(Ljava/lang/String;)V

    return-object v0

    :cond_0
    if-eqz p2, :cond_6

    if-eqz p3, :cond_6

    if-nez p4, :cond_1

    goto/16 :goto_0

    :cond_1
    invoke-virtual {p2}, Landroid/content/ComponentName;->flattenToString()Ljava/lang/String;

    move-result-object v2

    const-string v3, "ALLOW "

    invoke-static {v3, v2}, Llyiahf/vczjk/u81;->OooOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p2}, Landroid/content/ComponentName;->flattenToShortString()Ljava/lang/String;

    move-result-object v4

    invoke-static {v3, v4}, Llyiahf/vczjk/u81;->OooOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    filled-new-array {v2, v3}, [Ljava/lang/String;

    move-result-object v2

    invoke-interface {v1, v2}, Lgithub/tornaco/android/thanos/core/persist/i/SetRepo;->has([Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_2

    new-instance p1, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

    sget-object p2, Lgithub/tornaco/android/thanos/core/app/start/StartResult;->BYPASS_USER_RULE:Lgithub/tornaco/android/thanos/core/app/start/StartResult;

    invoke-direct {p1, p2, p3}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;-><init>(Lgithub/tornaco/android/thanos/core/app/start/StartResult;Ljava/lang/String;)V

    return-object p1

    :cond_2
    invoke-virtual {p2}, Landroid/content/ComponentName;->flattenToString()Ljava/lang/String;

    move-result-object v2

    const-string v3, "DENY "

    invoke-static {v3, v2}, Llyiahf/vczjk/u81;->OooOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p2}, Landroid/content/ComponentName;->flattenToShortString()Ljava/lang/String;

    move-result-object v4

    invoke-static {v3, v4}, Llyiahf/vczjk/u81;->OooOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    filled-new-array {v2, v3}, [Ljava/lang/String;

    move-result-object v2

    invoke-interface {v1, v2}, Lgithub/tornaco/android/thanos/core/persist/i/SetRepo;->has([Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_3

    new-instance p1, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

    sget-object p2, Lgithub/tornaco/android/thanos/core/app/start/StartResult;->BLOCKED_USER_RULE:Lgithub/tornaco/android/thanos/core/app/start/StartResult;

    invoke-direct {p1, p2, p3}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;-><init>(Lgithub/tornaco/android/thanos/core/app/start/StartResult;Ljava/lang/String;)V

    return-object p1

    :cond_3
    invoke-static {p2, p3, p4}, Llyiahf/vczjk/qx7;->OooOOO0(Landroid/content/ComponentName;Ljava/lang/String;Ljava/lang/String;)[Ljava/lang/String;

    move-result-object p2

    invoke-interface {v1, p2}, Lgithub/tornaco/android/thanos/core/persist/i/SetRepo;->has([Ljava/lang/Object;)Z

    move-result p2

    if-eqz p2, :cond_4

    new-instance p1, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

    sget-object p2, Lgithub/tornaco/android/thanos/core/app/start/StartResult;->BYPASS_USER_RULE:Lgithub/tornaco/android/thanos/core/app/start/StartResult;

    invoke-direct {p1, p2, p3}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;-><init>(Lgithub/tornaco/android/thanos/core/app/start/StartResult;Ljava/lang/String;)V

    return-object p1

    :cond_4
    invoke-static {p3, p4}, Llyiahf/vczjk/qx7;->OooOO0o(Ljava/lang/String;Ljava/lang/String;)[Ljava/lang/String;

    move-result-object p2

    invoke-interface {v1, p2}, Lgithub/tornaco/android/thanos/core/persist/i/SetRepo;->has([Ljava/lang/Object;)Z

    move-result p2

    if-eqz p2, :cond_5

    new-instance p1, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

    sget-object p2, Lgithub/tornaco/android/thanos/core/app/start/StartResult;->BLOCKED_USER_RULE:Lgithub/tornaco/android/thanos/core/app/start/StartResult;

    invoke-direct {p1, p2, p3}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;-><init>(Lgithub/tornaco/android/thanos/core/app/start/StartResult;Ljava/lang/String;)V

    return-object p1

    :cond_5
    sget-object p2, Lgithub/tornaco/android/thanos/core/push/PushChannel;->FCM_GCM:Lgithub/tornaco/android/thanos/core/push/PushChannel;

    invoke-virtual {p2, p1}, Lgithub/tornaco/android/thanos/core/push/PushChannel;->match(Landroid/content/Intent;)Z

    move-result p1

    if-eqz p1, :cond_6

    invoke-static {p3}, Llyiahf/vczjk/qx7;->OooOOO(Ljava/lang/String;)[Ljava/lang/String;

    move-result-object p1

    invoke-interface {v1, p1}, Lgithub/tornaco/android/thanos/core/persist/i/SetRepo;->has([Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_6

    new-instance p1, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

    sget-object p2, Lgithub/tornaco/android/thanos/core/app/start/StartResult;->BYPASS_USER_RULE:Lgithub/tornaco/android/thanos/core/app/start/StartResult;

    invoke-direct {p1, p2, p3}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;-><init>(Lgithub/tornaco/android/thanos/core/app/start/StartResult;Ljava/lang/String;)V

    return-object p1

    :cond_6
    :goto_0
    return-object v0
.end method

.method public OooOOOo(Llyiahf/vczjk/a74;)Llyiahf/vczjk/iaa;
    .locals 0

    iget-object p1, p1, Llyiahf/vczjk/a74;->OooO0o:Llyiahf/vczjk/dp8;

    if-eqz p1, :cond_1

    invoke-static {p1}, Llyiahf/vczjk/fu6;->OooOoO0(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/iaa;

    move-result-object p1

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    return-object p1

    :cond_1
    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/qx7;->OooOOO0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/sc9;

    invoke-virtual {p1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/rq2;

    return-object p1
.end method

.method public OooOOo(Landroidx/recyclerview/widget/o000oOoO;I)Llyiahf/vczjk/yu2;
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/qx7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ao8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ao8;->indexOfKey(Ljava/lang/Object;)I

    move-result p1

    const/4 v1, 0x0

    if-gez p1, :cond_0

    goto :goto_1

    :cond_0
    invoke-virtual {v0, p1}, Llyiahf/vczjk/ao8;->valueAt(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/sga;

    if-eqz v2, :cond_4

    iget v3, v2, Llyiahf/vczjk/sga;->OooO00o:I

    and-int v4, v3, p2

    if-eqz v4, :cond_4

    not-int v4, p2

    and-int/2addr v3, v4

    iput v3, v2, Llyiahf/vczjk/sga;->OooO00o:I

    const/4 v4, 0x4

    if-ne p2, v4, :cond_1

    iget-object p2, v2, Llyiahf/vczjk/sga;->OooO0O0:Llyiahf/vczjk/yu2;

    goto :goto_0

    :cond_1
    const/16 v4, 0x8

    if-ne p2, v4, :cond_3

    iget-object p2, v2, Llyiahf/vczjk/sga;->OooO0OO:Llyiahf/vczjk/yu2;

    :goto_0
    and-int/lit8 v3, v3, 0xc

    if-nez v3, :cond_2

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ao8;->removeAt(I)Ljava/lang/Object;

    const/4 p1, 0x0

    iput p1, v2, Llyiahf/vczjk/sga;->OooO00o:I

    iput-object v1, v2, Llyiahf/vczjk/sga;->OooO0O0:Llyiahf/vczjk/yu2;

    iput-object v1, v2, Llyiahf/vczjk/sga;->OooO0OO:Llyiahf/vczjk/yu2;

    sget-object p1, Llyiahf/vczjk/sga;->OooO0Oo:Llyiahf/vczjk/tz6;

    invoke-virtual {p1, v2}, Llyiahf/vczjk/tz6;->release(Ljava/lang/Object;)Z

    :cond_2
    return-object p2

    :cond_3
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string p2, "Must provide flag PRE or POST"

    invoke-direct {p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_4
    :goto_1
    return-object v1
.end method

.method public OooOOo0(Llyiahf/vczjk/t4a;Llyiahf/vczjk/a74;)Llyiahf/vczjk/uk4;
    .locals 1

    const-string v0, "typeParameter"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "typeAttr"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/w4a;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/w4a;-><init>(Llyiahf/vczjk/t4a;Llyiahf/vczjk/a74;)V

    iget-object p1, p0, Llyiahf/vczjk/qx7;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/l45;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/l45;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/uk4;

    return-object p1
.end method

.method public OooOOoo(Landroidx/recyclerview/widget/o000oOoO;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/qx7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ao8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ao8;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/sga;

    if-nez p1, :cond_0

    return-void

    :cond_0
    iget v0, p1, Llyiahf/vczjk/sga;->OooO00o:I

    and-int/lit8 v0, v0, -0x2

    iput v0, p1, Llyiahf/vczjk/sga;->OooO00o:I

    return-void
.end method

.method public OooOo0(Llyiahf/vczjk/i5a;Ljava/util/List;Llyiahf/vczjk/a74;)Llyiahf/vczjk/gh8;
    .locals 16

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move-object/from16 v2, p3

    new-instance v3, Llyiahf/vczjk/gh8;

    invoke-direct {v3}, Llyiahf/vczjk/gh8;-><init>()V

    invoke-interface/range {p2 .. p2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v4

    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_16

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/uk4;

    invoke-virtual {v4}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v5

    invoke-interface {v5}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v5

    instance-of v6, v5, Llyiahf/vczjk/by0;

    if-eqz v6, :cond_14

    iget-object v2, v2, Llyiahf/vczjk/a74;->OooO0o0:Ljava/util/Set;

    invoke-virtual {v4}, Llyiahf/vczjk/uk4;->o00000O()Llyiahf/vczjk/iaa;

    move-result-object v5

    instance-of v6, v5, Llyiahf/vczjk/k23;

    const-string v9, "getType(...)"

    const/16 v11, 0xa

    const-string v12, "getParameters(...)"

    if-eqz v6, :cond_c

    move-object v6, v5

    check-cast v6, Llyiahf/vczjk/k23;

    iget-object v14, v6, Llyiahf/vczjk/k23;->OooOOO:Llyiahf/vczjk/dp8;

    invoke-virtual {v14}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v15

    invoke-interface {v15}, Llyiahf/vczjk/n3a;->OooO0OO()Ljava/util/List;

    move-result-object v15

    invoke-interface {v15}, Ljava/util/List;->isEmpty()Z

    move-result v15

    if-nez v15, :cond_5

    invoke-virtual {v14}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v15

    invoke-interface {v15}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v15

    if-nez v15, :cond_0

    goto :goto_2

    :cond_0
    invoke-virtual {v14}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v15

    invoke-interface {v15}, Llyiahf/vczjk/n3a;->OooO0OO()Ljava/util/List;

    move-result-object v15

    invoke-static {v15, v12}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v10, Ljava/util/ArrayList;

    invoke-static {v15, v11}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v7

    invoke-direct {v10, v7}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v15}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v7

    :goto_0
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    move-result v15

    if-eqz v15, :cond_4

    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v15

    check-cast v15, Llyiahf/vczjk/t4a;

    invoke-virtual {v4}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object v11

    invoke-interface {v15}, Llyiahf/vczjk/t4a;->getIndex()I

    move-result v8

    invoke-static {v8, v11}, Llyiahf/vczjk/d21;->o00oO0o(ILjava/util/List;)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/z4a;

    if-eqz v2, :cond_1

    invoke-interface {v2, v15}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v11

    if-eqz v11, :cond_1

    const/4 v11, 0x1

    goto :goto_1

    :cond_1
    const/4 v11, 0x0

    :goto_1
    if-eqz v8, :cond_2

    if-nez v11, :cond_2

    invoke-virtual {v1}, Llyiahf/vczjk/i5a;->OooO0o()Llyiahf/vczjk/g5a;

    move-result-object v11

    invoke-virtual {v8}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object v13

    invoke-static {v13, v9}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v11, v13}, Llyiahf/vczjk/g5a;->OooO0Oo(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/z4a;

    move-result-object v11

    if-nez v11, :cond_3

    :cond_2
    new-instance v8, Llyiahf/vczjk/f19;

    invoke-direct {v8, v15}, Llyiahf/vczjk/f19;-><init>(Llyiahf/vczjk/t4a;)V

    :cond_3
    invoke-virtual {v10, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    const/16 v11, 0xa

    goto :goto_0

    :cond_4
    const/4 v8, 0x2

    const/4 v11, 0x0

    invoke-static {v14, v10, v11, v8}, Llyiahf/vczjk/vt6;->OooOooo(Llyiahf/vczjk/dp8;Ljava/util/List;Llyiahf/vczjk/d3a;I)Llyiahf/vczjk/dp8;

    move-result-object v14

    :cond_5
    :goto_2
    iget-object v6, v6, Llyiahf/vczjk/k23;->OooOOOO:Llyiahf/vczjk/dp8;

    invoke-virtual {v6}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v7

    invoke-interface {v7}, Llyiahf/vczjk/n3a;->OooO0OO()Ljava/util/List;

    move-result-object v7

    invoke-interface {v7}, Ljava/util/List;->isEmpty()Z

    move-result v7

    if-nez v7, :cond_b

    invoke-virtual {v6}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v7

    invoke-interface {v7}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v7

    if-nez v7, :cond_6

    goto :goto_5

    :cond_6
    invoke-virtual {v6}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v7

    invoke-interface {v7}, Llyiahf/vczjk/n3a;->OooO0OO()Ljava/util/List;

    move-result-object v7

    invoke-static {v7, v12}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v8, Ljava/util/ArrayList;

    const/16 v10, 0xa

    invoke-static {v7, v10}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v10

    invoke-direct {v8, v10}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v7}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v7

    :goto_3
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    move-result v10

    if-eqz v10, :cond_a

    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/t4a;

    invoke-virtual {v4}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object v11

    invoke-interface {v10}, Llyiahf/vczjk/t4a;->getIndex()I

    move-result v12

    invoke-static {v12, v11}, Llyiahf/vczjk/d21;->o00oO0o(ILjava/util/List;)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Llyiahf/vczjk/z4a;

    if-eqz v2, :cond_7

    invoke-interface {v2, v10}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v12

    if-eqz v12, :cond_7

    const/4 v12, 0x1

    goto :goto_4

    :cond_7
    const/4 v12, 0x0

    :goto_4
    if-eqz v11, :cond_8

    if-nez v12, :cond_8

    invoke-virtual {v1}, Llyiahf/vczjk/i5a;->OooO0o()Llyiahf/vczjk/g5a;

    move-result-object v12

    invoke-virtual {v11}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object v13

    invoke-static {v13, v9}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v12, v13}, Llyiahf/vczjk/g5a;->OooO0Oo(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/z4a;

    move-result-object v12

    if-nez v12, :cond_9

    :cond_8
    new-instance v11, Llyiahf/vczjk/f19;

    invoke-direct {v11, v10}, Llyiahf/vczjk/f19;-><init>(Llyiahf/vczjk/t4a;)V

    :cond_9
    invoke-virtual {v8, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_3

    :cond_a
    const/4 v10, 0x2

    const/4 v11, 0x0

    invoke-static {v6, v8, v11, v10}, Llyiahf/vczjk/vt6;->OooOooo(Llyiahf/vczjk/dp8;Ljava/util/List;Llyiahf/vczjk/d3a;I)Llyiahf/vczjk/dp8;

    move-result-object v6

    :cond_b
    :goto_5
    invoke-static {v14, v6}, Llyiahf/vczjk/so8;->OooOoOO(Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)Llyiahf/vczjk/iaa;

    move-result-object v2

    goto/16 :goto_9

    :cond_c
    instance-of v6, v5, Llyiahf/vczjk/dp8;

    if-eqz v6, :cond_13

    move-object v6, v5

    check-cast v6, Llyiahf/vczjk/dp8;

    invoke-virtual {v6}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v7

    invoke-interface {v7}, Llyiahf/vczjk/n3a;->OooO0OO()Ljava/util/List;

    move-result-object v7

    invoke-interface {v7}, Ljava/util/List;->isEmpty()Z

    move-result v7

    if-nez v7, :cond_12

    invoke-virtual {v6}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v7

    invoke-interface {v7}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v7

    if-nez v7, :cond_d

    goto :goto_8

    :cond_d
    invoke-virtual {v6}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v7

    invoke-interface {v7}, Llyiahf/vczjk/n3a;->OooO0OO()Ljava/util/List;

    move-result-object v7

    invoke-static {v7, v12}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v8, Ljava/util/ArrayList;

    const/16 v10, 0xa

    invoke-static {v7, v10}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v10

    invoke-direct {v8, v10}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v7}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v7

    :goto_6
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    move-result v10

    if-eqz v10, :cond_11

    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/t4a;

    invoke-virtual {v4}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object v11

    invoke-interface {v10}, Llyiahf/vczjk/t4a;->getIndex()I

    move-result v12

    invoke-static {v12, v11}, Llyiahf/vczjk/d21;->o00oO0o(ILjava/util/List;)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Llyiahf/vczjk/z4a;

    if-eqz v2, :cond_e

    invoke-interface {v2, v10}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v12

    if-eqz v12, :cond_e

    const/4 v12, 0x1

    goto :goto_7

    :cond_e
    const/4 v12, 0x0

    :goto_7
    if-eqz v11, :cond_f

    if-nez v12, :cond_f

    invoke-virtual {v1}, Llyiahf/vczjk/i5a;->OooO0o()Llyiahf/vczjk/g5a;

    move-result-object v12

    invoke-virtual {v11}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object v13

    invoke-static {v13, v9}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v12, v13}, Llyiahf/vczjk/g5a;->OooO0Oo(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/z4a;

    move-result-object v12

    if-nez v12, :cond_10

    :cond_f
    new-instance v11, Llyiahf/vczjk/f19;

    invoke-direct {v11, v10}, Llyiahf/vczjk/f19;-><init>(Llyiahf/vczjk/t4a;)V

    :cond_10
    invoke-virtual {v8, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_6

    :cond_11
    const/4 v10, 0x2

    const/4 v11, 0x0

    invoke-static {v6, v8, v11, v10}, Llyiahf/vczjk/vt6;->OooOooo(Llyiahf/vczjk/dp8;Ljava/util/List;Llyiahf/vczjk/d3a;I)Llyiahf/vczjk/dp8;

    move-result-object v2

    goto :goto_9

    :cond_12
    :goto_8
    move-object v2, v6

    :goto_9
    invoke-static {v2, v5}, Llyiahf/vczjk/qu6;->OooOOO(Llyiahf/vczjk/iaa;Llyiahf/vczjk/uk4;)Llyiahf/vczjk/iaa;

    move-result-object v2

    sget-object v4, Llyiahf/vczjk/cda;->OooOOOO:Llyiahf/vczjk/cda;

    invoke-virtual {v1, v2, v4}, Llyiahf/vczjk/i5a;->OooO0oO(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)Llyiahf/vczjk/uk4;

    move-result-object v1

    invoke-virtual {v3, v1}, Llyiahf/vczjk/gh8;->add(Ljava/lang/Object;)Z

    goto :goto_a

    :cond_13
    new-instance v1, Llyiahf/vczjk/k61;

    invoke-direct {v1}, Ljava/lang/RuntimeException;-><init>()V

    throw v1

    :cond_14
    instance-of v4, v5, Llyiahf/vczjk/t4a;

    if-eqz v4, :cond_16

    iget-object v4, v2, Llyiahf/vczjk/a74;->OooO0o0:Ljava/util/Set;

    if-eqz v4, :cond_15

    invoke-interface {v4, v5}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v4

    const/4 v6, 0x1

    if-ne v4, v6, :cond_15

    invoke-virtual {v0, v2}, Llyiahf/vczjk/qx7;->OooOOOo(Llyiahf/vczjk/a74;)Llyiahf/vczjk/iaa;

    move-result-object v1

    invoke-virtual {v3, v1}, Llyiahf/vczjk/gh8;->add(Ljava/lang/Object;)Z

    goto :goto_a

    :cond_15
    check-cast v5, Llyiahf/vczjk/t4a;

    invoke-interface {v5}, Llyiahf/vczjk/t4a;->getUpperBounds()Ljava/util/List;

    move-result-object v4

    const-string v5, "getUpperBounds(...)"

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0, v1, v4, v2}, Llyiahf/vczjk/qx7;->OooOo0(Llyiahf/vczjk/i5a;Ljava/util/List;Llyiahf/vczjk/a74;)Llyiahf/vczjk/gh8;

    move-result-object v1

    invoke-virtual {v3, v1}, Llyiahf/vczjk/gh8;->addAll(Ljava/util/Collection;)Z

    :cond_16
    :goto_a
    invoke-virtual {v3}, Llyiahf/vczjk/gh8;->OooO0O0()Llyiahf/vczjk/gh8;

    move-result-object v1

    return-object v1
.end method

.method public OooOo00(Landroidx/recyclerview/widget/o000oOoO;)V
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/qx7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/i65;

    invoke-virtual {v0}, Llyiahf/vczjk/i65;->OooO0oo()I

    move-result v1

    const/4 v2, 0x1

    sub-int/2addr v1, v2

    :goto_0
    if-ltz v1, :cond_1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/i65;->OooO(I)Ljava/lang/Object;

    move-result-object v3

    if-ne p1, v3, :cond_0

    iget-object v3, v0, Llyiahf/vczjk/i65;->OooOOOO:[Ljava/lang/Object;

    aget-object v4, v3, v1

    sget-object v5, Llyiahf/vczjk/m6a;->OooO0OO:Ljava/lang/Object;

    if-eq v4, v5, :cond_1

    aput-object v5, v3, v1

    iput-boolean v2, v0, Llyiahf/vczjk/i65;->OooOOO0:Z

    goto :goto_1

    :cond_0
    add-int/lit8 v1, v1, -0x1

    goto :goto_0

    :cond_1
    :goto_1
    iget-object v0, p0, Llyiahf/vczjk/qx7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ao8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ao8;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/sga;

    if-eqz p1, :cond_2

    const/4 v0, 0x0

    iput v0, p1, Llyiahf/vczjk/sga;->OooO00o:I

    const/4 v0, 0x0

    iput-object v0, p1, Llyiahf/vczjk/sga;->OooO0O0:Llyiahf/vczjk/yu2;

    iput-object v0, p1, Llyiahf/vczjk/sga;->OooO0OO:Llyiahf/vczjk/yu2;

    sget-object v0, Llyiahf/vczjk/sga;->OooO0Oo:Llyiahf/vczjk/tz6;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/tz6;->release(Ljava/lang/Object;)Z

    :cond_2
    return-void
.end method

.method public OooOo0O(Llyiahf/vczjk/gt1;Z)V
    .locals 10

    iget-object v0, p0, Llyiahf/vczjk/qx7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ol0;

    const/4 v1, 0x0

    if-eqz p2, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/ol0;->OooO0Oo()Z

    move-result p2

    if-eqz p2, :cond_0

    const/4 p2, 0x1

    goto :goto_0

    :cond_0
    move p2, v1

    :goto_0
    iget-object p1, p1, Llyiahf/vczjk/gt1;->OooOOO0:Llyiahf/vczjk/ft1;

    iget-object v2, p1, Llyiahf/vczjk/x13;->OooOOO:[Ljava/lang/Object;

    array-length v2, v2

    if-eqz p2, :cond_1

    invoke-static {v2}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object v3

    const-string v4, "  size: "

    invoke-virtual {v4, v3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v0, v3}, Llyiahf/vczjk/ol0;->OooO0OO(Ljava/lang/String;)V

    :cond_1
    invoke-virtual {v0, v2}, Llyiahf/vczjk/ol0;->OooOOO0(I)I

    move v3, v1

    :goto_1
    if-ge v3, v2, :cond_9

    invoke-virtual {p1, v3}, Llyiahf/vczjk/x13;->OooO0o0(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/hj1;

    const/16 v5, 0x20

    if-eqz p2, :cond_3

    invoke-static {v3}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    move-result-object v6

    invoke-static {v4}, Llyiahf/vczjk/qx7;->OooOOOO(Llyiahf/vczjk/hj1;)I

    move-result v7

    const/16 v8, 0x1e

    if-ne v7, v8, :cond_2

    const-string v7, "null"

    goto :goto_2

    :cond_2
    new-instance v7, Ljava/lang/StringBuilder;

    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v4}, Llyiahf/vczjk/hj1;->OooO0o0()Ljava/lang/String;

    move-result-object v8

    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v7, v5}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-interface {v4}, Llyiahf/vczjk/ss9;->OooO00o()Ljava/lang/String;

    move-result-object v8

    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v7

    :goto_2
    new-instance v8, Ljava/lang/StringBuilder;

    const-string v9, "  ["

    invoke-direct {v8, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v8, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v6, "] "

    invoke-virtual {v8, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v8, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v0, v6}, Llyiahf/vczjk/ol0;->OooO0OO(Ljava/lang/String;)V

    :cond_3
    invoke-static {v4}, Llyiahf/vczjk/qx7;->OooOOOO(Llyiahf/vczjk/hj1;)I

    move-result v6

    const/4 v7, 0x3

    if-eqz v6, :cond_7

    const/4 v8, 0x6

    if-eq v6, v8, :cond_7

    const/4 v8, 0x2

    if-eq v6, v8, :cond_7

    if-eq v6, v7, :cond_6

    const/4 v8, 0x4

    if-eq v6, v8, :cond_7

    const/16 v7, 0x10

    if-eq v6, v7, :cond_5

    const/16 v5, 0x11

    if-eq v6, v5, :cond_4

    iget-object v5, p0, Llyiahf/vczjk/qx7;->OooOOO0:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/t92;

    packed-switch v6, :pswitch_data_0

    new-instance p1, Ljava/lang/RuntimeException;

    const-string p2, "Shouldn\'t happen"

    invoke-direct {p1, p2}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    throw p1

    :pswitch_0
    check-cast v4, Llyiahf/vczjk/ht1;

    iget v4, v4, Llyiahf/vczjk/rt1;->OooOOO0:I

    shl-int/lit8 v4, v4, 0x5

    or-int/2addr v4, v6

    invoke-virtual {v0, v4}, Llyiahf/vczjk/ol0;->OooO(I)V

    goto/16 :goto_4

    :pswitch_1
    invoke-virtual {v0, v6}, Llyiahf/vczjk/ol0;->OooO(I)V

    goto/16 :goto_4

    :pswitch_2
    invoke-virtual {v0, v6}, Llyiahf/vczjk/ol0;->OooO(I)V

    new-instance p1, Ljava/lang/ClassCastException;

    invoke-direct {p1}, Ljava/lang/ClassCastException;-><init>()V

    throw p1

    :pswitch_3
    invoke-virtual {v0, v6}, Llyiahf/vczjk/ol0;->OooO(I)V

    check-cast v4, Llyiahf/vczjk/gt1;

    invoke-virtual {p0, v4, v1}, Llyiahf/vczjk/qx7;->OooOo0O(Llyiahf/vczjk/gt1;Z)V

    goto/16 :goto_4

    :pswitch_4
    new-instance p1, Ljava/lang/ClassCastException;

    invoke-direct {p1}, Ljava/lang/ClassCastException;-><init>()V

    throw p1

    :pswitch_5
    iget-object v5, v5, Llyiahf/vczjk/t92;->OooO:Llyiahf/vczjk/bj5;

    check-cast v4, Llyiahf/vczjk/wt1;

    invoke-virtual {v5, v4}, Llyiahf/vczjk/bj5;->OooOO0o(Llyiahf/vczjk/wt1;)I

    move-result v4

    int-to-long v4, v4

    invoke-static {v0, v6, v4, v5}, Llyiahf/vczjk/r02;->Oooo0OO(Llyiahf/vczjk/ol0;IJ)V

    goto/16 :goto_4

    :pswitch_6
    iget-object v5, v5, Llyiahf/vczjk/t92;->OooO0oo:Llyiahf/vczjk/ix2;

    check-cast v4, Llyiahf/vczjk/lt1;

    invoke-virtual {v5, v4}, Llyiahf/vczjk/ix2;->OooOO0o(Llyiahf/vczjk/lt1;)I

    move-result v4

    int-to-long v4, v4

    invoke-static {v0, v6, v4, v5}, Llyiahf/vczjk/r02;->Oooo0OO(Llyiahf/vczjk/ol0;IJ)V

    goto/16 :goto_4

    :pswitch_7
    iget-object v5, v5, Llyiahf/vczjk/t92;->OooO0o:Llyiahf/vczjk/ce7;

    check-cast v4, Llyiahf/vczjk/au1;

    invoke-virtual {v5, v4}, Llyiahf/vczjk/ce7;->OooOOO0(Llyiahf/vczjk/au1;)I

    move-result v4

    int-to-long v4, v4

    invoke-static {v0, v6, v4, v5}, Llyiahf/vczjk/r02;->Oooo0OO(Llyiahf/vczjk/ol0;IJ)V

    goto :goto_4

    :pswitch_8
    iget-object v5, v5, Llyiahf/vczjk/t92;->OooO0o0:Llyiahf/vczjk/ce7;

    check-cast v4, Llyiahf/vczjk/zt1;

    invoke-virtual {v5, v4}, Llyiahf/vczjk/ce7;->OooOO0o(Llyiahf/vczjk/zt1;)I

    move-result v4

    int-to-long v4, v4

    invoke-static {v0, v6, v4, v5}, Llyiahf/vczjk/r02;->Oooo0OO(Llyiahf/vczjk/ol0;IJ)V

    goto :goto_4

    :pswitch_9
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p1, Ljava/lang/ClassCastException;

    invoke-direct {p1}, Ljava/lang/ClassCastException;-><init>()V

    throw p1

    :pswitch_a
    iget-object p1, v5, Llyiahf/vczjk/t92;->OooO0oO:Llyiahf/vczjk/ce7;

    new-instance p1, Ljava/lang/ClassCastException;

    invoke-direct {p1}, Ljava/lang/ClassCastException;-><init>()V

    throw p1

    :cond_4
    check-cast v4, Llyiahf/vczjk/kt1;

    iget-wide v4, v4, Llyiahf/vczjk/st1;->OooOOO0:J

    invoke-static {v0, v6, v4, v5}, Llyiahf/vczjk/r02;->Oooo0O0(Llyiahf/vczjk/ol0;IJ)V

    goto :goto_4

    :cond_5
    check-cast v4, Llyiahf/vczjk/mt1;

    iget v4, v4, Llyiahf/vczjk/rt1;->OooOOO0:I

    int-to-long v7, v4

    shl-long v4, v7, v5

    invoke-static {v0, v6, v4, v5}, Llyiahf/vczjk/r02;->Oooo0O0(Llyiahf/vczjk/ol0;IJ)V

    goto :goto_4

    :cond_6
    check-cast v4, Llyiahf/vczjk/tt1;

    invoke-virtual {v4}, Llyiahf/vczjk/tt1;->OooO0oo()J

    move-result-wide v4

    invoke-static {v0, v6, v4, v5}, Llyiahf/vczjk/r02;->Oooo0OO(Llyiahf/vczjk/ol0;IJ)V

    goto :goto_4

    :cond_7
    check-cast v4, Llyiahf/vczjk/tt1;

    invoke-virtual {v4}, Llyiahf/vczjk/tt1;->OooO0oo()J

    move-result-wide v4

    const/16 v8, 0x3f

    shr-long v8, v4, v8

    xor-long/2addr v8, v4

    invoke-static {v8, v9}, Ljava/lang/Long;->numberOfLeadingZeros(J)I

    move-result v8

    rsub-int/lit8 v8, v8, 0x48

    shr-int/lit8 v7, v8, 0x3

    add-int/lit8 v8, v7, -0x1

    shl-int/lit8 v8, v8, 0x5

    or-int/2addr v6, v8

    invoke-virtual {v0, v6}, Llyiahf/vczjk/ol0;->OooO(I)V

    :goto_3
    if-lez v7, :cond_8

    long-to-int v6, v4

    int-to-byte v6, v6

    invoke-virtual {v0, v6}, Llyiahf/vczjk/ol0;->OooO(I)V

    const/16 v6, 0x8

    shr-long/2addr v4, v6

    add-int/lit8 v7, v7, -0x1

    goto :goto_3

    :cond_8
    :goto_4
    add-int/lit8 v3, v3, 0x1

    goto/16 :goto_1

    :cond_9
    if-eqz p2, :cond_a

    invoke-virtual {v0}, Llyiahf/vczjk/ol0;->OooO0o0()V

    :cond_a
    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x15
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
