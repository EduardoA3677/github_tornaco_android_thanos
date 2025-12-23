.class public final Llyiahf/vczjk/l96;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/m96;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/m96;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/m96;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/l96;->this$0:Llyiahf/vczjk/m96;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    sget-object v0, Llyiahf/vczjk/m96;->OooO0oO:Llyiahf/vczjk/tp3;

    iget-object v1, p0, Llyiahf/vczjk/l96;->this$0:Llyiahf/vczjk/m96;

    monitor-enter v0

    :try_start_0
    sget-object v2, Llyiahf/vczjk/m96;->OooO0o:Ljava/util/LinkedHashSet;

    iget-object v1, v1, Llyiahf/vczjk/m96;->OooO0o0:Llyiahf/vczjk/sc9;

    invoke-virtual {v1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/zp6;

    iget-object v1, v1, Llyiahf/vczjk/zp6;->OooOOO0:Llyiahf/vczjk/jm0;

    invoke-virtual {v1}, Llyiahf/vczjk/jm0;->OooOOoo()Ljava/lang/String;

    move-result-object v1

    invoke-interface {v2, v1}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v0

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :catchall_0
    move-exception v1

    monitor-exit v0

    throw v1
.end method
