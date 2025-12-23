.class public final Llyiahf/vczjk/xf1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $to:Llyiahf/vczjk/wp5;

.field final synthetic this$0:Llyiahf/vczjk/zf1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zf1;Llyiahf/vczjk/wp5;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/xf1;->this$0:Llyiahf/vczjk/zf1;

    iput-object p2, p0, Llyiahf/vczjk/xf1;->$to:Llyiahf/vczjk/wp5;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/xf1;->this$0:Llyiahf/vczjk/zf1;

    iget-object v1, p0, Llyiahf/vczjk/xf1;->$to:Llyiahf/vczjk/wp5;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v1, p0, Llyiahf/vczjk/xf1;->$to:Llyiahf/vczjk/wp5;

    const/4 v2, 0x0

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v1, 0x0

    invoke-static {v0, v2, v1}, Llyiahf/vczjk/zf1;->OooO0O0(Llyiahf/vczjk/zf1;Llyiahf/vczjk/ps6;Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
