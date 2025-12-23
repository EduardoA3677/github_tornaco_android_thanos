.class public final Llyiahf/vczjk/yq1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/hr1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hr1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/yq1;->this$0:Llyiahf/vczjk/hr1;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Ljava/util/List;

    iget-object v0, p0, Llyiahf/vczjk/yq1;->this$0:Llyiahf/vczjk/hr1;

    iget-object v0, v0, Llyiahf/vczjk/hr1;->OooOooo:Llyiahf/vczjk/lx4;

    invoke-virtual {v0}, Llyiahf/vczjk/lx4;->OooO0Oo()Llyiahf/vczjk/nm9;

    move-result-object v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/yq1;->this$0:Llyiahf/vczjk/hr1;

    iget-object v0, v0, Llyiahf/vczjk/hr1;->OooOooo:Llyiahf/vczjk/lx4;

    invoke-virtual {v0}, Llyiahf/vczjk/lx4;->OooO0Oo()Llyiahf/vczjk/nm9;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object v0, v0, Llyiahf/vczjk/nm9;->OooO00o:Llyiahf/vczjk/mm9;

    invoke-interface {p1, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    const/4 p1, 0x1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1
.end method
