.class public final Llyiahf/vczjk/ma;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/xa;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xa;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ma;->this$0:Llyiahf/vczjk/xa;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/ma;->this$0:Llyiahf/vczjk/xa;

    invoke-static {v0}, Llyiahf/vczjk/bua;->OooOOO0(Llyiahf/vczjk/xa;)J

    move-result-wide v0

    new-instance v2, Llyiahf/vczjk/b24;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/b24;-><init>(J)V

    return-object v2
.end method
