.class public final Llyiahf/vczjk/b41;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/g41;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/g41;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/b41;->this$0:Llyiahf/vczjk/g41;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/p86;

    iget-wide v0, p1, Llyiahf/vczjk/p86;->OooO00o:J

    iget-object p1, p0, Llyiahf/vczjk/b41;->this$0:Llyiahf/vczjk/g41;

    iget-object p1, p1, Llyiahf/vczjk/g41;->OoooOO0:Llyiahf/vczjk/le3;

    if-eqz p1, :cond_0

    invoke-interface {p1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/b41;->this$0:Llyiahf/vczjk/g41;

    iget-boolean v0, p1, Llyiahf/vczjk/g41;->OoooOOO:Z

    if-eqz v0, :cond_1

    sget-object v0, Llyiahf/vczjk/ch1;->OooOO0o:Llyiahf/vczjk/l39;

    invoke-static {p1, v0}, Llyiahf/vczjk/t51;->OooOo(Llyiahf/vczjk/ug1;Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/jm3;

    const/4 v0, 0x0

    invoke-interface {p1, v0}, Llyiahf/vczjk/jm3;->OooO00o(I)V

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
