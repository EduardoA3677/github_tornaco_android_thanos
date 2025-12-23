.class public final Llyiahf/vczjk/c89;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/d89;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/d89;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/c89;->this$0:Llyiahf/vczjk/d89;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/ro4;

    check-cast p2, Llyiahf/vczjk/d89;

    iget-object p2, p0, Llyiahf/vczjk/c89;->this$0:Llyiahf/vczjk/d89;

    iget-object v0, p1, Llyiahf/vczjk/ro4;->OoooO:Llyiahf/vczjk/fp4;

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/fp4;

    iget-object v1, p2, Llyiahf/vczjk/d89;->OooO00o:Llyiahf/vczjk/g89;

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/fp4;-><init>(Llyiahf/vczjk/ro4;Llyiahf/vczjk/g89;)V

    iput-object v0, p1, Llyiahf/vczjk/ro4;->OoooO:Llyiahf/vczjk/fp4;

    :cond_0
    iput-object v0, p2, Llyiahf/vczjk/d89;->OooO0O0:Llyiahf/vczjk/fp4;

    iget-object p1, p0, Llyiahf/vczjk/c89;->this$0:Llyiahf/vczjk/d89;

    invoke-virtual {p1}, Llyiahf/vczjk/d89;->OooO00o()Llyiahf/vczjk/fp4;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/fp4;->OooO0Oo()V

    iget-object p1, p0, Llyiahf/vczjk/c89;->this$0:Llyiahf/vczjk/d89;

    invoke-virtual {p1}, Llyiahf/vczjk/d89;->OooO00o()Llyiahf/vczjk/fp4;

    move-result-object p1

    iget-object p2, p0, Llyiahf/vczjk/c89;->this$0:Llyiahf/vczjk/d89;

    iget-object p2, p2, Llyiahf/vczjk/d89;->OooO00o:Llyiahf/vczjk/g89;

    iget-object v0, p1, Llyiahf/vczjk/fp4;->OooOOOO:Llyiahf/vczjk/g89;

    if-eq v0, p2, :cond_1

    iput-object p2, p1, Llyiahf/vczjk/fp4;->OooOOOO:Llyiahf/vczjk/g89;

    const/4 p2, 0x0

    invoke-virtual {p1, p2}, Llyiahf/vczjk/fp4;->OooO0o0(Z)V

    const/4 v0, 0x7

    iget-object p1, p1, Llyiahf/vczjk/fp4;->OooOOO0:Llyiahf/vczjk/ro4;

    invoke-static {p1, p2, v0}, Llyiahf/vczjk/ro4;->OoooOOO(Llyiahf/vczjk/ro4;ZI)V

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
