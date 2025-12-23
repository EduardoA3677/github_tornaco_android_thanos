.class public final Llyiahf/vczjk/f75;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $iterations:I

.field final synthetic this$0:Llyiahf/vczjk/k75;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/k75;I)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/f75;->this$0:Llyiahf/vczjk/k75;

    iput p2, p0, Llyiahf/vczjk/f75;->$iterations:I

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->longValue()J

    move-result-wide v0

    iget-object p1, p0, Llyiahf/vczjk/f75;->this$0:Llyiahf/vczjk/k75;

    iget v2, p0, Llyiahf/vczjk/f75;->$iterations:I

    invoke-static {p1, v2, v0, v1}, Llyiahf/vczjk/k75;->OooO00o(Llyiahf/vczjk/k75;IJ)Z

    move-result p1

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1
.end method
