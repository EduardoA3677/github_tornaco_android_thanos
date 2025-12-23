.class public final Llyiahf/vczjk/oe;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/df3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/pe;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/pe;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/oe;->this$0:Llyiahf/vczjk/pe;

    const/4 p1, 0x4

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/ba3;

    check-cast p2, Llyiahf/vczjk/ib3;

    check-cast p3, Llyiahf/vczjk/cb3;

    iget p3, p3, Llyiahf/vczjk/cb3;->OooO00o:I

    check-cast p4, Llyiahf/vczjk/db3;

    iget p4, p4, Llyiahf/vczjk/db3;->OooO00o:I

    iget-object v0, p0, Llyiahf/vczjk/oe;->this$0:Llyiahf/vczjk/pe;

    iget-object v0, v0, Llyiahf/vczjk/pe;->OooO0o0:Llyiahf/vczjk/aa3;

    check-cast v0, Llyiahf/vczjk/ea3;

    invoke-virtual {v0, p1, p2, p3, p4}, Llyiahf/vczjk/ea3;->OooO0O0(Llyiahf/vczjk/ba3;Llyiahf/vczjk/ib3;II)Llyiahf/vczjk/i6a;

    move-result-object p1

    instance-of p2, p1, Llyiahf/vczjk/h6a;

    const-string p3, "null cannot be cast to non-null type android.graphics.Typeface"

    if-nez p2, :cond_0

    new-instance p2, Llyiahf/vczjk/ed5;

    iget-object p4, p0, Llyiahf/vczjk/oe;->this$0:Llyiahf/vczjk/pe;

    iget-object p4, p4, Llyiahf/vczjk/pe;->OooOO0:Llyiahf/vczjk/ed5;

    invoke-direct {p2, p1, p4}, Llyiahf/vczjk/ed5;-><init>(Llyiahf/vczjk/i6a;Llyiahf/vczjk/ed5;)V

    iget-object p1, p0, Llyiahf/vczjk/oe;->this$0:Llyiahf/vczjk/pe;

    iput-object p2, p1, Llyiahf/vczjk/pe;->OooOO0:Llyiahf/vczjk/ed5;

    iget-object p1, p2, Llyiahf/vczjk/ed5;->OooOOOo:Ljava/lang/Object;

    invoke-static {p1, p3}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Landroid/graphics/Typeface;

    return-object p1

    :cond_0
    check-cast p1, Llyiahf/vczjk/h6a;

    iget-object p1, p1, Llyiahf/vczjk/h6a;->OooOOO0:Ljava/lang/Object;

    invoke-static {p1, p3}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Landroid/graphics/Typeface;

    return-object p1
.end method
