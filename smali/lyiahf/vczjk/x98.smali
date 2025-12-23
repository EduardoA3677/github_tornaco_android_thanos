.class public final Llyiahf/vczjk/x98;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/z98;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/z98;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/x98;->this$0:Llyiahf/vczjk/z98;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/x98;->this$0:Llyiahf/vczjk/z98;

    invoke-virtual {v0}, Llyiahf/vczjk/z98;->OooO0o()I

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/x98;->this$0:Llyiahf/vczjk/z98;

    iget-object v1, v1, Llyiahf/vczjk/z98;->OooO0Oo:Llyiahf/vczjk/qr5;

    check-cast v1, Llyiahf/vczjk/bw8;

    invoke-virtual {v1}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v1

    if-ge v0, v1, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    return-object v0
.end method
