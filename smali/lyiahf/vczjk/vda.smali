.class public final Llyiahf/vczjk/vda;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/wda;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wda;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/vda;->this$0:Llyiahf/vczjk/wda;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/vda;->this$0:Llyiahf/vczjk/wda;

    iget v1, v0, Llyiahf/vczjk/wda;->OooOo:I

    iget-object v0, v0, Llyiahf/vczjk/wda;->OooOo0:Llyiahf/vczjk/qr5;

    check-cast v0, Llyiahf/vczjk/bw8;

    invoke-virtual {v0}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v0

    if-ne v1, v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/vda;->this$0:Llyiahf/vczjk/wda;

    iget-object v1, v0, Llyiahf/vczjk/wda;->OooOo0:Llyiahf/vczjk/qr5;

    check-cast v1, Llyiahf/vczjk/bw8;

    invoke-virtual {v1}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v1

    add-int/lit8 v1, v1, 0x1

    iget-object v0, v0, Llyiahf/vczjk/wda;->OooOo0:Llyiahf/vczjk/qr5;

    check-cast v0, Llyiahf/vczjk/bw8;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/bw8;->OooOo00(I)V

    :cond_0
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
