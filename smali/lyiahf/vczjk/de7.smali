.class public final Llyiahf/vczjk/de7;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO0OO:Llyiahf/vczjk/de7;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/uz5;

.field public final OooO0O0:Ljava/util/concurrent/ConcurrentHashMap;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/de7;

    invoke-direct {v0}, Llyiahf/vczjk/de7;-><init>()V

    sput-object v0, Llyiahf/vczjk/de7;->OooO0OO:Llyiahf/vczjk/de7;

    return-void
.end method

.method public constructor <init>()V
    .locals 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/de7;->OooO0O0:Ljava/util/concurrent/ConcurrentHashMap;

    new-instance v0, Llyiahf/vczjk/uz5;

    const/4 v1, 0x2

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/uz5;-><init>(IB)V

    iput-object v0, p0, Llyiahf/vczjk/de7;->OooO00o:Llyiahf/vczjk/uz5;

    return-void
.end method


# virtual methods
.method public final OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/u88;
    .locals 9

    const-string v0, "messageType"

    invoke-static {p1, v0}, Llyiahf/vczjk/z24;->OooO00o(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/de7;->OooO0O0:Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {v0, p1}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/u88;

    if-nez v1, :cond_c

    iget-object v1, p0, Llyiahf/vczjk/de7;->OooO00o:Llyiahf/vczjk/uz5;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v2, Llyiahf/vczjk/v88;->OooO00o:Ljava/lang/Class;

    const-class v2, Llyiahf/vczjk/wg3;

    invoke-virtual {v2, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v3

    if-nez v3, :cond_1

    sget-object v3, Llyiahf/vczjk/v88;->OooO00o:Ljava/lang/Class;

    if-eqz v3, :cond_1

    invoke-virtual {v3, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v3

    if-eqz v3, :cond_0

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Message classes must extend GeneratedMessage or GeneratedMessageLite"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    :goto_0
    iget-object v1, v1, Llyiahf/vczjk/uz5;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ab5;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/ab5;->messageInfoFor(Ljava/lang/Class;)Llyiahf/vczjk/og7;

    move-result-object v3

    iget v1, v3, Llyiahf/vczjk/og7;->OooO0Oo:I

    const/4 v4, 0x2

    and-int/2addr v1, v4

    const-string v5, "Protobuf runtime is not correctly loaded."

    if-ne v1, v4, :cond_4

    invoke-virtual {v2, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v1

    iget-object v2, v3, Llyiahf/vczjk/og7;->OooO00o:Llyiahf/vczjk/wg3;

    if-eqz v1, :cond_2

    sget-object v1, Llyiahf/vczjk/v88;->OooO0OO:Llyiahf/vczjk/c9a;

    sget-object v3, Llyiahf/vczjk/lu2;->OooO00o:Llyiahf/vczjk/ku2;

    new-instance v4, Llyiahf/vczjk/ui5;

    invoke-direct {v4, v1, v3, v2}, Llyiahf/vczjk/ui5;-><init>(Llyiahf/vczjk/c9a;Llyiahf/vczjk/ku2;Llyiahf/vczjk/wg3;)V

    goto/16 :goto_2

    :cond_2
    sget-object v1, Llyiahf/vczjk/v88;->OooO0O0:Llyiahf/vczjk/c9a;

    sget-object v3, Llyiahf/vczjk/lu2;->OooO0O0:Llyiahf/vczjk/ku2;

    if-eqz v3, :cond_3

    new-instance v4, Llyiahf/vczjk/ui5;

    invoke-direct {v4, v1, v3, v2}, Llyiahf/vczjk/ui5;-><init>(Llyiahf/vczjk/c9a;Llyiahf/vczjk/ku2;Llyiahf/vczjk/wg3;)V

    goto :goto_2

    :cond_3
    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-direct {p1, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_4
    invoke-virtual {v2, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v1

    const/4 v2, 0x1

    const/4 v4, 0x0

    if-eqz v1, :cond_7

    move-object v1, v4

    sget-object v4, Llyiahf/vczjk/q06;->OooO0O0:Llyiahf/vczjk/p06;

    sget-object v5, Llyiahf/vczjk/b15;->OooO0O0:Llyiahf/vczjk/a15;

    sget-object v6, Llyiahf/vczjk/v88;->OooO0OO:Llyiahf/vczjk/c9a;

    invoke-virtual {v3}, Llyiahf/vczjk/og7;->OooO00o()I

    move-result v7

    invoke-static {v7}, Llyiahf/vczjk/ix8;->OooOo(I)I

    move-result v7

    if-eq v7, v2, :cond_5

    sget-object v1, Llyiahf/vczjk/lu2;->OooO00o:Llyiahf/vczjk/ku2;

    :cond_5
    move-object v7, v1

    sget-object v8, Llyiahf/vczjk/sb5;->OooO0O0:Llyiahf/vczjk/rb5;

    sget-object v1, Llyiahf/vczjk/ti5;->OooOOO:[I

    instance-of v1, v3, Llyiahf/vczjk/og7;

    if-eqz v1, :cond_6

    invoke-static/range {v3 .. v8}, Llyiahf/vczjk/ti5;->OooOo00(Llyiahf/vczjk/og7;Llyiahf/vczjk/p06;Llyiahf/vczjk/a15;Llyiahf/vczjk/c9a;Llyiahf/vczjk/ku2;Llyiahf/vczjk/rb5;)Llyiahf/vczjk/ti5;

    move-result-object v4

    goto :goto_2

    :cond_6
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p1, Ljava/lang/ClassCastException;

    invoke-direct {p1}, Ljava/lang/ClassCastException;-><init>()V

    throw p1

    :cond_7
    move-object v1, v4

    sget-object v4, Llyiahf/vczjk/q06;->OooO00o:Llyiahf/vczjk/p06;

    move-object v6, v5

    sget-object v5, Llyiahf/vczjk/b15;->OooO00o:Llyiahf/vczjk/a15;

    move-object v7, v6

    sget-object v6, Llyiahf/vczjk/v88;->OooO0O0:Llyiahf/vczjk/c9a;

    invoke-virtual {v3}, Llyiahf/vczjk/og7;->OooO00o()I

    move-result v8

    invoke-static {v8}, Llyiahf/vczjk/ix8;->OooOo(I)I

    move-result v8

    if-eq v8, v2, :cond_8

    sget-object v1, Llyiahf/vczjk/lu2;->OooO0O0:Llyiahf/vczjk/ku2;

    if-eqz v1, :cond_9

    :cond_8
    move-object v7, v1

    goto :goto_1

    :cond_9
    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-direct {p1, v7}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :goto_1
    sget-object v8, Llyiahf/vczjk/sb5;->OooO00o:Llyiahf/vczjk/rb5;

    sget-object v1, Llyiahf/vczjk/ti5;->OooOOO:[I

    instance-of v1, v3, Llyiahf/vczjk/og7;

    if-eqz v1, :cond_b

    invoke-static/range {v3 .. v8}, Llyiahf/vczjk/ti5;->OooOo00(Llyiahf/vczjk/og7;Llyiahf/vczjk/p06;Llyiahf/vczjk/a15;Llyiahf/vczjk/c9a;Llyiahf/vczjk/ku2;Llyiahf/vczjk/rb5;)Llyiahf/vczjk/ti5;

    move-result-object v4

    :goto_2
    invoke-virtual {v0, p1, v4}, Ljava/util/concurrent/ConcurrentHashMap;->putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/u88;

    if-eqz p1, :cond_a

    return-object p1

    :cond_a
    return-object v4

    :cond_b
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p1, Ljava/lang/ClassCastException;

    invoke-direct {p1}, Ljava/lang/ClassCastException;-><init>()V

    throw p1

    :cond_c
    return-object v1
.end method
