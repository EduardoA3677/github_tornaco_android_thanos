.class public final Llyiahf/vczjk/am6;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/km6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/km6;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/am6;->this$0:Llyiahf/vczjk/km6;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/am6;->this$0:Llyiahf/vczjk/km6;

    iget-object v0, v0, Llyiahf/vczjk/km6;->OooO00o:Llyiahf/vczjk/dw4;

    invoke-virtual {v0}, Llyiahf/vczjk/dw4;->OooO0oO()Llyiahf/vczjk/sv4;

    move-result-object v0

    iget v0, v0, Llyiahf/vczjk/sv4;->OooOOO:I

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    return-object v0
.end method
