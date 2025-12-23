.class public final Llyiahf/vczjk/fh2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $density:Llyiahf/vczjk/f62;

.field final synthetic $drawerState:Llyiahf/vczjk/li2;

.field final synthetic $maxValue:F

.field final synthetic $minValue:F


# direct methods
.method public constructor <init>(Llyiahf/vczjk/li2;Llyiahf/vczjk/f62;F)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/fh2;->$drawerState:Llyiahf/vczjk/li2;

    iput-object p2, p0, Llyiahf/vczjk/fh2;->$density:Llyiahf/vczjk/f62;

    iput p3, p0, Llyiahf/vczjk/fh2;->$minValue:F

    const/4 p1, 0x0

    iput p1, p0, Llyiahf/vczjk/fh2;->$maxValue:F

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/fh2;->$drawerState:Llyiahf/vczjk/li2;

    iget-object v1, p0, Llyiahf/vczjk/fh2;->$density:Llyiahf/vczjk/f62;

    iput-object v1, v0, Llyiahf/vczjk/li2;->OooO0O0:Llyiahf/vczjk/f62;

    new-instance v0, Llyiahf/vczjk/eh2;

    iget v1, p0, Llyiahf/vczjk/fh2;->$minValue:F

    iget v2, p0, Llyiahf/vczjk/fh2;->$maxValue:F

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/eh2;-><init>(FF)V

    new-instance v1, Llyiahf/vczjk/lb5;

    new-instance v2, Ljava/util/LinkedHashMap;

    invoke-direct {v2}, Ljava/util/LinkedHashMap;-><init>()V

    sget-object v3, Llyiahf/vczjk/ni2;->OooOOO0:Llyiahf/vczjk/ni2;

    iget v4, v0, Llyiahf/vczjk/eh2;->$minValue:F

    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v4

    invoke-interface {v2, v3, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    sget-object v3, Llyiahf/vczjk/ni2;->OooOOO:Llyiahf/vczjk/ni2;

    iget v0, v0, Llyiahf/vczjk/eh2;->$maxValue:F

    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v0

    invoke-interface {v2, v3, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-direct {v1, v2}, Llyiahf/vczjk/lb5;-><init>(Ljava/util/Map;)V

    iget-object v0, p0, Llyiahf/vczjk/fh2;->$drawerState:Llyiahf/vczjk/li2;

    iget-object v0, v0, Llyiahf/vczjk/li2;->OooO00o:Llyiahf/vczjk/d9;

    invoke-virtual {v0}, Llyiahf/vczjk/d9;->OooO0o0()F

    move-result v2

    invoke-static {v2}, Ljava/lang/Float;->isNaN(F)Z

    move-result v2

    iget-object v3, v0, Llyiahf/vczjk/d9;->OooO0oo:Llyiahf/vczjk/w62;

    if-nez v2, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/d9;->OooO0o0()F

    move-result v2

    invoke-virtual {v1, v2}, Llyiahf/vczjk/lb5;->OooO00o(F)Ljava/lang/Object;

    move-result-object v2

    if-nez v2, :cond_1

    invoke-virtual {v3}, Llyiahf/vczjk/w62;->getValue()Ljava/lang/Object;

    move-result-object v2

    goto :goto_0

    :cond_0
    invoke-virtual {v3}, Llyiahf/vczjk/w62;->getValue()Ljava/lang/Object;

    move-result-object v2

    :cond_1
    :goto_0
    invoke-virtual {v0}, Llyiahf/vczjk/d9;->OooO0Oo()Llyiahf/vczjk/lb5;

    move-result-object v3

    invoke-static {v3, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_3

    iget-object v3, v0, Llyiahf/vczjk/d9;->OooOOO0:Llyiahf/vczjk/qs5;

    check-cast v3, Llyiahf/vczjk/fw8;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    new-instance v1, Llyiahf/vczjk/b9;

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/b9;-><init>(Llyiahf/vczjk/d9;Ljava/lang/Object;)V

    iget-object v3, v0, Llyiahf/vczjk/d9;->OooO0o0:Llyiahf/vczjk/f34;

    iget-object v3, v3, Llyiahf/vczjk/f34;->OooO0O0:Llyiahf/vczjk/mt5;

    invoke-virtual {v3}, Llyiahf/vczjk/mt5;->OooO0o()Z

    move-result v4

    if-eqz v4, :cond_2

    const/4 v5, 0x0

    :try_start_0
    invoke-virtual {v1}, Llyiahf/vczjk/b9;->OooO00o()Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {v3, v5}, Llyiahf/vczjk/mt5;->OooO0Oo(Ljava/lang/Object;)V

    goto :goto_1

    :catchall_0
    move-exception v0

    invoke-virtual {v3, v5}, Llyiahf/vczjk/mt5;->OooO0Oo(Ljava/lang/Object;)V

    throw v0

    :cond_2
    :goto_1
    if-nez v4, :cond_3

    invoke-virtual {v0, v2}, Llyiahf/vczjk/d9;->OooO0oo(Ljava/lang/Object;)V

    :cond_3
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
