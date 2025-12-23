.class public final Llyiahf/vczjk/db2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/eb2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/eb2;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/db2;->this$0:Llyiahf/vczjk/eb2;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/y96;

    iget-object p1, p0, Llyiahf/vczjk/db2;->this$0:Llyiahf/vczjk/eb2;

    iget-object v0, p1, Llyiahf/vczjk/eb2;->OooOOo0:Llyiahf/vczjk/ab2;

    iget-boolean v0, v0, Llyiahf/vczjk/ab2;->OooO00o:Z

    if-eqz v0, :cond_0

    iget-object p1, p1, Llyiahf/vczjk/eb2;->OooOOOo:Llyiahf/vczjk/le3;

    invoke-interface {p1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
