.class public final Llyiahf/vczjk/e50;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/f50;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/f50;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/e50;->this$0:Llyiahf/vczjk/f50;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/e50;->this$0:Llyiahf/vczjk/f50;

    iget-object v0, v0, Llyiahf/vczjk/f50;->OooOoOO:Llyiahf/vczjk/il5;

    const-string v1, "null cannot be cast to non-null type androidx.compose.ui.modifier.ModifierLocalConsumer"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/nl5;

    iget-object v1, p0, Llyiahf/vczjk/e50;->this$0:Llyiahf/vczjk/f50;

    invoke-interface {v0, v1}, Llyiahf/vczjk/nl5;->OooO0o(Llyiahf/vczjk/sl5;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
