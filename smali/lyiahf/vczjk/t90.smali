.class public final Llyiahf/vczjk/t90;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $textFieldValue:Llyiahf/vczjk/gl9;

.field final synthetic $textFieldValueState$delegate:Llyiahf/vczjk/qs5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/qs5;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gl9;Llyiahf/vczjk/qs5;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/t90;->$textFieldValue:Llyiahf/vczjk/gl9;

    iput-object p2, p0, Llyiahf/vczjk/t90;->$textFieldValueState$delegate:Llyiahf/vczjk/qs5;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/t90;->$textFieldValue:Llyiahf/vczjk/gl9;

    iget-wide v0, v0, Llyiahf/vczjk/gl9;->OooO0O0:J

    iget-object v2, p0, Llyiahf/vczjk/t90;->$textFieldValueState$delegate:Llyiahf/vczjk/qs5;

    invoke-interface {v2}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/gl9;

    iget-wide v2, v2, Llyiahf/vczjk/gl9;->OooO0O0:J

    invoke-static {v0, v1, v2, v3}, Llyiahf/vczjk/gn9;->OooO00o(JJ)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/t90;->$textFieldValue:Llyiahf/vczjk/gl9;

    iget-object v0, v0, Llyiahf/vczjk/gl9;->OooO0OO:Llyiahf/vczjk/gn9;

    iget-object v1, p0, Llyiahf/vczjk/t90;->$textFieldValueState$delegate:Llyiahf/vczjk/qs5;

    invoke-interface {v1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/gl9;

    iget-object v1, v1, Llyiahf/vczjk/gl9;->OooO0OO:Llyiahf/vczjk/gn9;

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/t90;->$textFieldValueState$delegate:Llyiahf/vczjk/qs5;

    iget-object v1, p0, Llyiahf/vczjk/t90;->$textFieldValue:Llyiahf/vczjk/gl9;

    invoke-interface {v0, v1}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    :cond_1
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
