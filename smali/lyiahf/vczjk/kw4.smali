.class public final Llyiahf/vczjk/kw4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $key:Ljava/lang/Object;

.field final synthetic this$0:Llyiahf/vczjk/lw4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lw4;Ljava/lang/Object;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/kw4;->this$0:Llyiahf/vczjk/lw4;

    iput-object p2, p0, Llyiahf/vczjk/kw4;->$key:Ljava/lang/Object;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/qc2;

    iget-object p1, p0, Llyiahf/vczjk/kw4;->this$0:Llyiahf/vczjk/lw4;

    iget-object p1, p1, Llyiahf/vczjk/lw4;->OooO0OO:Llyiahf/vczjk/ks5;

    iget-object v0, p0, Llyiahf/vczjk/kw4;->$key:Ljava/lang/Object;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ks5;->OooO(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/kw4;->this$0:Llyiahf/vczjk/lw4;

    iget-object v0, p0, Llyiahf/vczjk/kw4;->$key:Ljava/lang/Object;

    new-instance v1, Llyiahf/vczjk/xb;

    const/4 v2, 0x5

    invoke-direct {v1, v2, p1, v0}, Llyiahf/vczjk/xb;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    return-object v1
.end method
