.class public final Llyiahf/vczjk/kq1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $manager:Llyiahf/vczjk/mk9;

.field final synthetic $show:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/mk9;ZI)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/kq1;->$manager:Llyiahf/vczjk/mk9;

    iput-boolean p2, p0, Llyiahf/vczjk/kq1;->$show:Z

    iput p3, p0, Llyiahf/vczjk/kq1;->$$changed:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object p2, p0, Llyiahf/vczjk/kq1;->$manager:Llyiahf/vczjk/mk9;

    iget-boolean v0, p0, Llyiahf/vczjk/kq1;->$show:Z

    iget v1, p0, Llyiahf/vczjk/kq1;->$$changed:I

    or-int/lit8 v1, v1, 0x1

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v1

    invoke-static {p2, v0, p1, v1}, Llyiahf/vczjk/sb;->OooOOO(Llyiahf/vczjk/mk9;ZLlyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
