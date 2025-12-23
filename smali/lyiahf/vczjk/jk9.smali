.class public final Llyiahf/vczjk/jk9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/mk9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/mk9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/jk9;->this$0:Llyiahf/vczjk/mk9;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/jk9;->this$0:Llyiahf/vczjk/mk9;

    iget-object v1, v0, Llyiahf/vczjk/mk9;->OooO:Llyiahf/vczjk/xr1;

    if-eqz v1, :cond_0

    sget-object v2, Llyiahf/vczjk/as1;->OooOOOo:Llyiahf/vczjk/as1;

    new-instance v3, Llyiahf/vczjk/ik9;

    const/4 v4, 0x0

    invoke-direct {v3, v0, v4}, Llyiahf/vczjk/ik9;-><init>(Llyiahf/vczjk/mk9;Llyiahf/vczjk/yo1;)V

    const/4 v0, 0x1

    invoke-static {v1, v4, v2, v3, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/jk9;->this$0:Llyiahf/vczjk/mk9;

    invoke-virtual {v0}, Llyiahf/vczjk/mk9;->OooOOO()V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
