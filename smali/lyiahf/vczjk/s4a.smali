.class public final Llyiahf/vczjk/s4a;
.super Llyiahf/vczjk/e4a;
.source "SourceFile"


# instance fields
.field public final OooO0OO:Llyiahf/vczjk/fc5;

.field public final OooO0Oo:Ljava/util/concurrent/ConcurrentHashMap;

.field public final OooO0o:Z

.field public final OooO0o0:Ljava/util/HashMap;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fc5;Llyiahf/vczjk/x64;Ljava/util/concurrent/ConcurrentHashMap;Ljava/util/HashMap;)V
    .locals 1

    invoke-virtual {p1}, Llyiahf/vczjk/ec5;->OooOOOO()Llyiahf/vczjk/a4a;

    move-result-object v0

    invoke-direct {p0, p2, v0}, Llyiahf/vczjk/e4a;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/a4a;)V

    iput-object p1, p0, Llyiahf/vczjk/s4a;->OooO0OO:Llyiahf/vczjk/fc5;

    iput-object p3, p0, Llyiahf/vczjk/s4a;->OooO0Oo:Ljava/util/concurrent/ConcurrentHashMap;

    iput-object p4, p0, Llyiahf/vczjk/s4a;->OooO0o0:Ljava/util/HashMap;

    sget-object p2, Llyiahf/vczjk/gc5;->Oooo00O:Llyiahf/vczjk/gc5;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ec5;->OooOOoo(Llyiahf/vczjk/gc5;)Z

    move-result p1

    iput-boolean p1, p0, Llyiahf/vczjk/s4a;->OooO0o:Z

    return-void
.end method


# virtual methods
.method public final OooO00o(Ljava/lang/Object;)Ljava/lang/String;
    .locals 0

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/s4a;->OooO0o0(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0O0(Ljava/lang/String;Llyiahf/vczjk/v72;)Llyiahf/vczjk/x64;
    .locals 0

    iget-boolean p2, p0, Llyiahf/vczjk/s4a;->OooO0o:Z

    if-eqz p2, :cond_0

    invoke-virtual {p1}, Ljava/lang/String;->toLowerCase()Ljava/lang/String;

    move-result-object p1

    :cond_0
    iget-object p2, p0, Llyiahf/vczjk/s4a;->OooO0o0:Ljava/util/HashMap;

    invoke-interface {p2, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/x64;

    return-object p1
.end method

.method public final OooO0OO()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/util/TreeSet;

    iget-object v1, p0, Llyiahf/vczjk/s4a;->OooO0o0:Ljava/util/HashMap;

    invoke-interface {v1}, Ljava/util/Map;->keySet()Ljava/util/Set;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/util/TreeSet;-><init>(Ljava/util/Collection;)V

    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0Oo(Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/String;
    .locals 0

    if-nez p2, :cond_0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/s4a;->OooO0o0(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/s4a;->OooO0o0(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0o0(Ljava/lang/Class;)Ljava/lang/String;
    .locals 5

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/s4a;->OooO0Oo:Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {v1, v0}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/String;

    if-nez v2, :cond_4

    iget-object v3, p0, Llyiahf/vczjk/e4a;->OooO00o:Llyiahf/vczjk/a4a;

    invoke-virtual {v3, p1}, Llyiahf/vczjk/a4a;->OooOO0O(Ljava/lang/reflect/Type;)Llyiahf/vczjk/x64;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object p1

    iget-object v3, p0, Llyiahf/vczjk/s4a;->OooO0OO:Llyiahf/vczjk/fc5;

    invoke-virtual {v3}, Llyiahf/vczjk/ec5;->OooOOo()Z

    move-result v4

    if-eqz v4, :cond_1

    invoke-virtual {v3, p1}, Llyiahf/vczjk/ec5;->OooOOOo(Ljava/lang/Class;)Llyiahf/vczjk/h90;

    move-result-object v2

    invoke-virtual {v3}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object v3

    iget-object v2, v2, Llyiahf/vczjk/h90;->OooO0o0:Llyiahf/vczjk/hm;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/yn;->o000oOoO(Llyiahf/vczjk/hm;)Ljava/lang/String;

    move-result-object v2

    :cond_1
    if-nez v2, :cond_3

    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p1

    const/16 v2, 0x2e

    invoke-virtual {p1, v2}, Ljava/lang/String;->lastIndexOf(I)I

    move-result v2

    if-gez v2, :cond_2

    :goto_0
    move-object v2, p1

    goto :goto_1

    :cond_2
    add-int/lit8 v2, v2, 0x1

    invoke-virtual {p1, v2}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object p1

    goto :goto_0

    :cond_3
    :goto_1
    invoke-virtual {v1, v0, v2}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_4
    return-object v2
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    const-class v0, Llyiahf/vczjk/s4a;

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/s4a;->OooO0o0:Ljava/util/HashMap;

    filled-new-array {v0, v1}, [Ljava/lang/Object;

    move-result-object v0

    const-string v1, "[%s; id-to-type=%s]"

    invoke-static {v1, v0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
