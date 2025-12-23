.class public final Llyiahf/vczjk/e6a;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $typefaceRequest:Llyiahf/vczjk/d6a;

.field final synthetic this$0:Llyiahf/vczjk/f6a;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/f6a;Llyiahf/vczjk/d6a;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/e6a;->this$0:Llyiahf/vczjk/f6a;

    iput-object p2, p0, Llyiahf/vczjk/e6a;->$typefaceRequest:Llyiahf/vczjk/d6a;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/i6a;

    iget-object v0, p0, Llyiahf/vczjk/e6a;->this$0:Llyiahf/vczjk/f6a;

    iget-object v1, v0, Llyiahf/vczjk/f6a;->OooO00o:Llyiahf/vczjk/sp3;

    iget-object v2, p0, Llyiahf/vczjk/e6a;->$typefaceRequest:Llyiahf/vczjk/d6a;

    monitor-enter v1

    :try_start_0
    invoke-interface {p1}, Llyiahf/vczjk/i6a;->OooO0o0()Z

    move-result v3

    if-eqz v3, :cond_0

    iget-object v0, v0, Llyiahf/vczjk/f6a;->OooO0O0:Llyiahf/vczjk/i95;

    invoke-virtual {v0, v2, p1}, Llyiahf/vczjk/i95;->OooO0OO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_0
    iget-object p1, v0, Llyiahf/vczjk/f6a;->OooO0O0:Llyiahf/vczjk/i95;

    invoke-virtual {p1, v2}, Llyiahf/vczjk/i95;->OooO0Oo(Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :goto_0
    monitor-exit v1

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :goto_1
    monitor-exit v1

    throw p1
.end method
