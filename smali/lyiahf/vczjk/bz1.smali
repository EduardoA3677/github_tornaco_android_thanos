.class public final Llyiahf/vczjk/bz1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/jz1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/jz1;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jz1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/bz1;->this$0:Llyiahf/vczjk/jz1;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 12

    iget-object v0, p0, Llyiahf/vczjk/bz1;->this$0:Llyiahf/vczjk/jz1;

    iget-object v0, v0, Llyiahf/vczjk/jz1;->OooO00o:Llyiahf/vczjk/m96;

    const-string v1, "There are multiple DataStores active for the same file: "

    iget-object v2, v0, Llyiahf/vczjk/m96;->OooO0o0:Llyiahf/vczjk/sc9;

    invoke-virtual {v2}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/zp6;

    iget-object v2, v2, Llyiahf/vczjk/zp6;->OooOOO0:Llyiahf/vczjk/jm0;

    invoke-virtual {v2}, Llyiahf/vczjk/jm0;->OooOOoo()Ljava/lang/String;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/m96;->OooO0oO:Llyiahf/vczjk/tp3;

    monitor-enter v3

    :try_start_0
    sget-object v4, Llyiahf/vczjk/m96;->OooO0o:Ljava/util/LinkedHashSet;

    invoke-interface {v4, v2}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_0

    invoke-interface {v4, v2}, Ljava/util/Set;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v3

    new-instance v6, Llyiahf/vczjk/p96;

    iget-object v7, v0, Llyiahf/vczjk/m96;->OooO00o:Llyiahf/vczjk/we4;

    iget-object v1, v0, Llyiahf/vczjk/m96;->OooO0o0:Llyiahf/vczjk/sc9;

    invoke-virtual {v1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v1

    move-object v8, v1

    check-cast v8, Llyiahf/vczjk/zp6;

    iget-object v9, v0, Llyiahf/vczjk/m96;->OooO0O0:Llyiahf/vczjk/j96;

    iget-object v1, v0, Llyiahf/vczjk/m96;->OooO0OO:Llyiahf/vczjk/ze3;

    iget-object v2, v0, Llyiahf/vczjk/m96;->OooO0o0:Llyiahf/vczjk/sc9;

    invoke-virtual {v2}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/zp6;

    iget-object v3, v0, Llyiahf/vczjk/m96;->OooO00o:Llyiahf/vczjk/we4;

    invoke-interface {v1, v2, v3}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    move-object v10, v1

    check-cast v10, Llyiahf/vczjk/yp8;

    new-instance v11, Llyiahf/vczjk/l96;

    invoke-direct {v11, v0}, Llyiahf/vczjk/l96;-><init>(Llyiahf/vczjk/m96;)V

    invoke-direct/range {v6 .. v11}, Llyiahf/vczjk/p96;-><init>(Llyiahf/vczjk/we4;Llyiahf/vczjk/zp6;Llyiahf/vczjk/j96;Llyiahf/vczjk/yp8;Llyiahf/vczjk/l96;)V

    return-object v6

    :catchall_0
    move-exception v0

    goto :goto_0

    :cond_0
    :try_start_1
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, ". You should either maintain your DataStore as a singleton or confirm that there is no two DataStore\'s active on the same file (by confirming that the scope is cancelled)."

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    new-instance v1, Ljava/lang/IllegalStateException;

    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :goto_0
    monitor-exit v3

    throw v0
.end method
