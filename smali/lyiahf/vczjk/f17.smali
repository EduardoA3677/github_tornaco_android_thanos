.class public final Llyiahf/vczjk/f17;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $backCallBack:Llyiahf/vczjk/d17;

.field final synthetic $backDispatcher:Llyiahf/vczjk/ha6;

.field final synthetic $lifecycleOwner:Llyiahf/vczjk/uy4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ha6;Llyiahf/vczjk/uy4;Llyiahf/vczjk/d17;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/f17;->$backDispatcher:Llyiahf/vczjk/ha6;

    iput-object p2, p0, Llyiahf/vczjk/f17;->$lifecycleOwner:Llyiahf/vczjk/uy4;

    iput-object p3, p0, Llyiahf/vczjk/f17;->$backCallBack:Llyiahf/vczjk/d17;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/qc2;

    iget-object p1, p0, Llyiahf/vczjk/f17;->$backDispatcher:Llyiahf/vczjk/ha6;

    iget-object v0, p0, Llyiahf/vczjk/f17;->$lifecycleOwner:Llyiahf/vczjk/uy4;

    iget-object v1, p0, Llyiahf/vczjk/f17;->$backCallBack:Llyiahf/vczjk/d17;

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/ha6;->OooO00o(Llyiahf/vczjk/uy4;Llyiahf/vczjk/y96;)V

    iget-object p1, p0, Llyiahf/vczjk/f17;->$backCallBack:Llyiahf/vczjk/d17;

    new-instance v0, Llyiahf/vczjk/x;

    const/16 v1, 0xa

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/x;-><init>(Ljava/lang/Object;I)V

    return-object v0
.end method
