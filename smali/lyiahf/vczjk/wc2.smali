.class public final Llyiahf/vczjk/wc2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $androidxRegistry:Llyiahf/vczjk/e68;

.field final synthetic $key:Ljava/lang/String;

.field final synthetic $registered:Z


# direct methods
.method public constructor <init>(ZLlyiahf/vczjk/e68;Ljava/lang/String;)V
    .locals 0

    iput-boolean p1, p0, Llyiahf/vczjk/wc2;->$registered:Z

    iput-object p2, p0, Llyiahf/vczjk/wc2;->$androidxRegistry:Llyiahf/vczjk/e68;

    iput-object p3, p0, Llyiahf/vczjk/wc2;->$key:Ljava/lang/String;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget-boolean v0, p0, Llyiahf/vczjk/wc2;->$registered:Z

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/wc2;->$androidxRegistry:Llyiahf/vczjk/e68;

    iget-object v1, p0, Llyiahf/vczjk/wc2;->$key:Ljava/lang/String;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v2, "key"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, v0, Llyiahf/vczjk/e68;->OooO00o:Llyiahf/vczjk/g68;

    iget-object v2, v0, Llyiahf/vczjk/g68;->OooO0OO:Llyiahf/vczjk/rp3;

    monitor-enter v2

    :try_start_0
    iget-object v0, v0, Llyiahf/vczjk/g68;->OooO0Oo:Ljava/util/LinkedHashMap;

    invoke-interface {v0, v1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/d68;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v2

    goto :goto_0

    :catchall_0
    move-exception v0

    monitor-exit v2

    throw v0

    :cond_0
    :goto_0
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
